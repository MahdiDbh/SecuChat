"""Client SecuChat en ligne de commande (TLS 1.3 + chiffrement de bout en bout).

- SecuChatClient : logique réseau et crypto, testable sans terminal ;
- run_cli / main : interface texte avec les commandes du README.
"""

import argparse
import asyncio
import contextlib
import getpass
import hashlib
import json
import ssl
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from nacl.public import PrivateKey, PublicKey
from nacl.pwhash import argon2id
from pydantic import ValidationError

from secuchat import config, crypto, protocol
from secuchat.crypto import CryptoError
from secuchat.protocol import ProtocolError

REQUEST_TIMEOUT = 15  # secondes d'attente max d'une réponse du serveur
MAX_CLOCK_SKEW = 300  # un message plus vieux (ou plus "futur") que 5 min est refusé
ENVELOPE_VERSION = 1

HELP = """Commandes :
  /register <user>        crée un compte
  /login <user>           se connecte
  /join <salon>           rejoint un salon
  /leave <salon>          quitte un salon
  /msg <salon> <texte>    message chiffré à tout le salon
  /dm <user> <texte>      message direct chiffré
  /users <salon>          membres du salon
  /quit                   déconnexion"""


class ClientError(Exception):
    """Erreur montrable à l'utilisateur."""


@dataclass(frozen=True)
class Incoming:
    """Ce que le client affiche : message déchiffré, événement ou avertissement."""

    kind: str  # "room", "dm", "event", "warning"
    text: str
    sender: str | None = None
    room: str | None = None


def sanitize(text: str) -> str:
    """Neutralise les caractères de contrôle (séquences ANSI, \\r, \\n...) avant affichage.

    Les espaces Unicode deviennent un espace simple, les autres caractères invisibles
    (catégories C*) sont supprimés.
    """
    out = []
    for ch in text:
        category = unicodedata.category(ch)
        if category.startswith("Z"):
            out.append(" ")
        elif not category.startswith("C"):
            out.append(ch)
    return "".join(out)


def format_incoming(item: Incoming) -> str:
    if item.kind == "room":
        return f"[#{item.room}] {item.sender}: {item.text}"
    if item.kind == "dm":
        return f"[DM] {item.sender}: {item.text}"
    if item.kind == "event":
        return f"* {item.text}"
    return f"! {item.text}"


def make_client_ssl_context(ca: str | Path) -> ssl.SSLContext:
    """TLS 1.3 minimum, certificat serveur vérifié avec la CA fournie."""
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx  # check_hostname=True et CERT_REQUIRED par défaut


class SecuChatClient:
    """Connexion au serveur, requêtes et chiffrement de bout en bout."""

    def __init__(
        self,
        keys_dir: Path | None = None,
        on_incoming: Callable[[Incoming], None] | None = None,
        kdf_opslimit: int = argon2id.OPSLIMIT_MODERATE,
        kdf_memlimit: int = argon2id.MEMLIMIT_MODERATE,
        clock: Callable[[], float] = time.time,
    ):
        self.keys_dir = Path(keys_dir or config.KEYS_DIR)
        self.on_incoming = on_incoming or (lambda item: print(format_incoming(item)))
        self._kdf = {"opslimit": kdf_opslimit, "memlimit": kdf_memlimit}
        self._clock = clock
        self.username: str | None = None
        self._token: str | None = None
        self._private_key: PrivateKey | None = None
        self._pubkeys: dict[str, PublicKey] = {}  # cache de la session
        self._seen: set[bytes] = set()  # anti-rejeu : empreintes des messages déjà reçus
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._responses: asyncio.Queue = asyncio.Queue()
        self._pushes: asyncio.Queue = asyncio.Queue()
        self._lock = asyncio.Lock()
        self._tasks: list[asyncio.Task] = []

    # --- Connexion ---
    async def connect(
        self, host: str, port: int, ca: str | Path, server_hostname: str | None = None
    ) -> None:
        try:
            ssl_ctx = make_client_ssl_context(ca)
        except (OSError, ssl.SSLError):
            raise ClientError(f"cannot load CA certificate ({ca})") from None
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port, ssl=ssl_ctx,
                    server_hostname=server_hostname or host,
                    limit=config.MAX_MESSAGE_SIZE,
                ),
                config.CONNECT_TIMEOUT,
            )
        except ssl.SSLCertVerificationError:
            raise ClientError("server certificate verification failed") from None
        except (OSError, TimeoutError) as exc:
            raise ClientError(f"cannot connect to server ({type(exc).__name__})") from None
        self._tasks = [
            asyncio.create_task(self._reader_loop()),
            asyncio.create_task(self._push_loop()),
        ]

    async def close(self) -> None:
        for task in self._tasks:
            task.cancel()
        if self._writer is not None:
            self._writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._writer.wait_closed(), 2)
        self._private_key = None
        self._token = None

    # --- Commandes ---
    async def register(self, username: str, password: str) -> None:
        """Génère la paire de clés, sauvegarde la clé privée chiffrée, crée le compte."""
        if not config.is_valid_username(username):
            raise ClientError("invalid username (3-32 chars: letters, digits, _ -)")
        if not config.is_valid_password(password):
            raise ClientError("password must be 12 to 128 characters")
        path = crypto.key_path_for(username, self.keys_dir)
        if path.exists():
            raise ClientError(f"a key already exists for {username} ({path})")
        private_key = crypto.generate_keypair()
        crypto.save_private_key(private_key, password, path, **self._kdf)
        try:
            await self._request(
                protocol.RegisterRequest,
                username=username, password=password, pubkey=crypto.public_key_b64(private_key),
            )
        except ClientError:
            path.unlink(missing_ok=True)  # compte non créé : on ne garde pas la clé
            raise

    async def login(self, username: str, password: str) -> None:
        """Déverrouille la clé privée locale puis ouvre la session."""
        try:
            private_key = crypto.load_private_key(
                password, crypto.key_path_for(username, self.keys_dir)
            )
        except CryptoError as exc:
            raise ClientError(f"cannot unlock local private key: {exc}") from None
        reply = await self._request(
            protocol.LoginRequest, username=username, password=password
        )
        self.username, self._token, self._private_key = username, reply.token, private_key
        self._pubkeys = {}

    async def logout(self) -> None:
        if self._token:
            with contextlib.suppress(ClientError):
                await self._request(protocol.LogoutRequest, token=self._token)
        self.username = self._token = self._private_key = None

    async def join(self, room: str) -> None:
        await self._request(protocol.JoinRequest, token=self._need_token(), room=room)

    async def leave(self, room: str) -> None:
        await self._request(protocol.LeaveRequest, token=self._need_token(), room=room)

    async def users(self, room: str) -> list[str]:
        reply = await self._request(protocol.UsersRequest, token=self._need_token(), room=room)
        return reply.users or []

    async def send_room(self, room: str, text: str) -> int:
        """Chiffre le texte une fois par membre du salon. Renvoie le nombre de destinataires."""
        members = [m for m in await self.users(room) if m != self.username]
        if not members:
            raise ClientError("no other member in this room")
        keys = await self._get_pubkeys(members)
        ts = int(self._clock())
        plaintext = self._envelope(ts, f"room:{room}", text)
        payloads = {
            name: crypto.encrypt_for(key, self._private_key, plaintext)
            for name, key in keys.items()
        }
        await self._request(
            protocol.RoomMsgRequest,
            token=self._need_token(), room=room, payloads=payloads, nonce_ts=ts,
        )
        return len(payloads)

    async def send_dm(self, to: str, text: str) -> None:
        keys = await self._get_pubkeys([to])
        if to not in keys:
            raise ClientError("unknown user")
        ts = int(self._clock())
        payload = crypto.encrypt_for(keys[to], self._private_key, self._envelope(ts, "dm", text))
        await self._request(
            protocol.DmRequest, token=self._need_token(), to=to, payload=payload, nonce_ts=ts
        )

    # --- Réception ---
    async def _reader_loop(self) -> None:
        """Lit le flux : réponses -> _responses, messages poussés -> _pushes."""
        try:
            while True:
                line = await self._reader.readline()
                if not line:
                    break
                try:
                    msg = protocol.decode_server(line)
                except ProtocolError:
                    continue  # message serveur invalide : ignoré
                queue = self._responses if msg.type in ("ok", "error") else self._pushes
                queue.put_nowait(msg)
        except (ConnectionError, ssl.SSLError, ValueError, asyncio.IncompleteReadError):
            pass
        finally:
            self._responses.put_nowait(None)
            self._pushes.put_nowait(None)

    async def _push_loop(self) -> None:
        while (msg := await self._pushes.get()) is not None:
            try:
                item = await self._handle_push(msg)
            except ClientError as exc:
                item = Incoming("warning", str(exc))
            if item is not None:
                self.on_incoming(item)
        self.on_incoming(Incoming("warning", "connection to server lost"))

    async def _handle_push(self, msg) -> Incoming | None:
        if msg.type == "event":
            verb = "joined" if msg.event == "join" else "left"
            if msg.event == "leave":
                self._pubkeys.pop(msg.username, None)
            return Incoming("event", f"{msg.username} {verb} #{msg.room}", msg.username, msg.room)
        if self._private_key is None:
            return None
        context = f"room:{msg.room}" if msg.type == "room_msg" else "dm"
        text = await self._open(msg.sender, msg.payload, msg.nonce_ts, context)
        kind = "room" if msg.type == "room_msg" else "dm"
        return Incoming(kind, text, msg.sender, getattr(msg, "room", None))

    async def _open(self, sender: str, payload: str, nonce_ts: int, context: str) -> str:
        """Déchiffre et vérifie l'enveloppe (horodatage, contexte, rejeu)."""
        keys = await self._get_pubkeys([sender])
        if sender not in keys:
            raise ClientError(f"message from {sender} rejected: unknown key")
        try:
            plaintext = crypto.decrypt_from(keys[sender], self._private_key, payload)
            env = json.loads(plaintext)
            ok = (
                isinstance(env, dict)
                and env.get("v") == ENVELOPE_VERSION
                and env.get("ts") == nonce_ts
                and env.get("ctx") == context
                and isinstance(env.get("text"), str)
            )
        except (CryptoError, ValueError):
            ok = False
        if not ok:
            raise ClientError(f"message from {sender} rejected: integrity check failed")
        if abs(self._clock() - nonce_ts) > MAX_CLOCK_SKEW:
            raise ClientError(f"message from {sender} rejected: too old")
        digest = hashlib.sha256(payload.encode()).digest()
        if digest in self._seen:
            raise ClientError(f"message from {sender} rejected: replayed")
        self._seen.add(digest)
        return sanitize(env["text"])

    # --- Outils ---
    async def _request(self, model: type, **fields):
        """Valide la requête localement, l'envoie et attend ok/error (une à la fois)."""
        if self._writer is None:
            raise ClientError("not connected")
        try:
            data = protocol.encode(model(type=_type_of(model), **fields))
        except ValidationError:
            raise ClientError("invalid input") from None
        except ProtocolError:
            raise ClientError("message too long") from None
        async with self._lock:
            try:
                self._writer.write(data)
                await self._writer.drain()
                reply = await asyncio.wait_for(self._responses.get(), REQUEST_TIMEOUT)
            except (ConnectionError, ssl.SSLError):
                reply = None
            except TimeoutError:
                raise ClientError("server did not answer") from None
        if reply is None:
            self._responses.put_nowait(None)  # les requêtes suivantes échouent aussi
            raise ClientError("connection to server lost")
        if reply.type == "error":
            raise ClientError(reply.message)
        return reply

    async def _get_pubkeys(self, usernames: list[str]) -> dict[str, PublicKey]:
        missing = [u for u in usernames if u not in self._pubkeys]
        if missing:
            reply = await self._request(
                protocol.GetPubkeysRequest, token=self._need_token(), usernames=missing
            )
            for name, value in (reply.pubkeys or {}).items():
                with contextlib.suppress(CryptoError):
                    self._pubkeys[name] = crypto.load_public_key(value)
        return {u: self._pubkeys[u] for u in usernames if u in self._pubkeys}

    def _need_token(self) -> str:
        if not self._token or self._private_key is None:
            raise ClientError("not logged in (use /login <user>)")
        return self._token

    @staticmethod
    def _envelope(ts: int, context: str, text: str) -> str:
        """Le timestamp et le contexte sont chiffrés avec le texte : le serveur ne peut
        ni rejouer un vieux message comme nouveau, ni le déplacer dans un autre salon."""
        return json.dumps({"v": ENVELOPE_VERSION, "ts": ts, "ctx": context, "text": text})


def _type_of(model: type) -> str:
    """Valeur du champ Literal 'type' d'un modèle du protocole."""
    return model.model_fields["type"].annotation.__args__[0]


# --- Interface en ligne de commande ---
def parse_command(line: str) -> tuple[str, list[str]]:
    """'/msg projet salut tout le monde' -> ('msg', ['projet', 'salut tout le monde'])."""
    line = line.strip()
    if not line.startswith("/"):
        return "", [line] if line else []
    parts = line[1:].split(maxsplit=1)
    if not parts:
        return "", []
    cmd, rest = parts[0].lower(), parts[1] if len(parts) > 1 else ""
    if cmd in ("msg", "dm"):
        args = rest.split(maxsplit=1)
    else:
        args = rest.split()
    return cmd, args


async def _ask_password(prompt: str = "Mot de passe : ") -> str:
    return await asyncio.to_thread(getpass.getpass, prompt)


async def handle_command(client: SecuChatClient, cmd: str, args: list[str]) -> bool:
    """Exécute une commande. Renvoie False pour quitter."""
    expected = {"register": 1, "login": 1, "join": 1, "leave": 1, "users": 1, "msg": 2, "dm": 2}
    if cmd == "quit":
        await client.logout()
        return False
    if cmd not in expected:
        print(HELP)
        return True
    if len(args) != expected[cmd]:
        print(f"Usage incorrect. {HELP}")
        return True

    if cmd == "register":
        password = await _ask_password()
        if password != await _ask_password("Confirmation : "):
            print("! Les mots de passe ne correspondent pas")
            return True
        await client.register(args[0], password)
        print(f"Compte {args[0]} créé. Connecte-toi avec /login {args[0]}")
    elif cmd == "login":
        await client.login(args[0], await _ask_password())
        print(f"Connecté en tant que {args[0]}")
    elif cmd == "join":
        await client.join(args[0])
        print(f"Tu as rejoint #{args[0]}")
    elif cmd == "leave":
        await client.leave(args[0])
        print(f"Tu as quitté #{args[0]}")
    elif cmd == "users":
        print(f"Membres de #{args[0]} : " + ", ".join(await client.users(args[0])))
    elif cmd == "msg":
        count = await client.send_room(args[0], args[1])
        print(f"(chiffré pour {count} destinataire(s))")
    elif cmd == "dm":
        await client.send_dm(args[0], args[1])
    return True


async def run_cli(args: argparse.Namespace) -> None:
    client = SecuChatClient(keys_dir=args.keys_dir)
    await client.connect(args.host, args.port, args.ca, args.server_name)
    print(f"Connecté à {args.host}:{args.port} (TLS 1.3, certificat vérifié). /help pour l'aide.")
    try:
        while True:
            try:
                line = await asyncio.to_thread(input, "> ")
            except EOFError:
                await client.logout()
                break
            cmd, cmd_args = parse_command(line)
            if not cmd and not cmd_args:
                continue
            try:
                if not await handle_command(client, cmd, cmd_args):
                    break
            except ClientError as exc:
                print(f"! Erreur : {exc}")
    finally:
        await client.close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Client SecuChat")
    parser.add_argument("--host", default=config.DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT)
    parser.add_argument("--ca", default=str(config.DEFAULT_CERT),
                        help="certificat (ou CA) du serveur à vérifier")
    parser.add_argument("--server-name", default=None,
                        help="nom attendu dans le certificat (défaut : --host)")
    parser.add_argument("--keys-dir", type=Path, default=config.KEYS_DIR)
    args = parser.parse_args(argv)
    try:
        asyncio.run(run_cli(args))
    except ClientError as exc:
        print(f"! Erreur : {exc}")
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
