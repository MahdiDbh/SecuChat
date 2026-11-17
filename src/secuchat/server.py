"""Serveur SecuChat : TLS 1.3, asyncio, routage des messages chiffrés (spec §5, §6.3).

Le serveur ne déchiffre jamais les messages : il vérifie l'identité et les droits,
puis relaie à chaque destinataire le contenu chiffré qui lui est destiné.
Les logs ne contiennent jamais de mot de passe, de jeton ni de contenu.
"""

import argparse
import asyncio
import contextlib
import logging
import ssl
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from secuchat import config, protocol
from secuchat.auth import INVALID_CREDENTIALS, INVALID_SESSION, AuthError, AuthService
from secuchat.db import Database
from secuchat.protocol import ProtocolError

logger = logging.getLogger("secuchat.server")

# Erreurs génériques renvoyées au client
ERR_INVALID = "invalid request"
ERR_FORBIDDEN = "forbidden"
ERR_UNAVAILABLE = "recipient unavailable"
ERR_INTERNAL = "internal error"
ERR_TOO_LARGE = "message too large"


@dataclass(eq=False)
class Connection:
    """Une connexion client et l'utilisateur authentifié dessus (s'il y en a un)."""

    writer: asyncio.StreamWriter
    peer: str
    username: str | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


def make_server_ssl_context(cert: str | Path, key: str | Path) -> ssl.SSLContext:
    """Contexte TLS serveur : TLS 1.3 minimum."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return ctx


class SecuChatServer:
    """Logique du serveur, indépendante du socket (testable)."""

    def __init__(
        self,
        db: Database,
        auth: AuthService,
        read_timeout: float = config.READ_TIMEOUT,
    ):
        self.db = db
        self.auth = auth
        self.read_timeout = read_timeout
        self.online: dict[str, Connection] = {}  # username -> connexion active
        self._connections: set[Connection] = set()
        self._ip_failures: dict[str, deque[float]] = {}
        self._handlers = {
            "register": self._on_register,
            "login": self._on_login,
            "logout": self._on_logout,
            "join": self._on_join,
            "leave": self._on_leave,
            "room_msg": self._on_room_msg,
            "dm": self._on_dm,
            "users": self._on_users,
            "get_pubkeys": self._on_get_pubkeys,
        }

    # --- Boucle par connexion ---
    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peername = writer.get_extra_info("peername")
        peer = str(peername[0]) if peername else "unknown"
        conn = Connection(writer=writer, peer=peer)

        if len(self._connections) >= config.MAX_CONNECTIONS:
            logger.warning("connection refused (too many connections) from %s", peer)
            await self._close(conn)
            return
        self._connections.add(conn)
        logger.info("connection from %s", peer)
        try:
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), self.read_timeout)
                except TimeoutError:
                    logger.info("read timeout, closing %s", peer)
                    break
                except (ValueError, asyncio.LimitOverrunError):
                    # Ligne > 64 Ko : le flux est désynchronisé, on coupe
                    logger.warning("oversized message from %s", peer)
                    await self._error(conn, ERR_TOO_LARGE)
                    break
                except (ConnectionError, ssl.SSLError):
                    break
                if not line:
                    break  # fin de connexion
                await self.dispatch(conn, line)
        finally:
            self._connections.discard(conn)
            self._unbind(conn)
            await self._close(conn)
            logger.info("connection closed %s", peer)

    async def dispatch(self, conn: Connection, line: bytes) -> None:
        """Valide une ligne et appelle le bon handler. Ne lève jamais d'exception."""
        try:
            msg = protocol.decode_client(line)
        except ProtocolError:
            logger.warning("invalid message from %s", conn.peer)
            await self._error(conn, ERR_INVALID)
            return
        try:
            await self._handlers[msg.type](conn, msg)
        except AuthError as exc:
            await self._error(conn, str(exc))  # déjà générique
        except Exception:
            # Le détail reste dans les logs serveur ; le client reçoit un message générique
            logger.exception("internal error while handling %s from %s", msg.type, conn.peer)
            await self._error(conn, ERR_INTERNAL)

    # --- Handlers ---
    async def _on_register(self, conn: Connection, msg: protocol.RegisterRequest) -> None:
        self.auth.register(msg.username, msg.password, msg.pubkey)
        await self._ok(conn, "register")

    async def _on_login(self, conn: Connection, msg: protocol.LoginRequest) -> None:
        if self._ip_blocked(conn.peer):
            logger.warning("login refused: too many failures from %s", conn.peer)
            raise AuthError(INVALID_CREDENTIALS)
        try:
            token = self.auth.login(msg.username, msg.password)
        except AuthError:
            self._ip_failures.setdefault(conn.peer, deque()).append(time.monotonic())
            raise
        self._unbind(conn)
        previous = self.online.get(msg.username)
        if previous is not None and previous is not conn:
            previous.username = None  # l'ancien jeton a été révoqué par auth.login
        conn.username = msg.username
        self.online[msg.username] = conn
        await self._ok(conn, "login", token=token)

    async def _on_logout(self, conn: Connection, msg: protocol.LogoutRequest) -> None:
        self._authenticate(conn, msg.token)
        self.auth.logout(msg.token)
        self._unbind(conn)
        await self._ok(conn, "logout")

    async def _on_join(self, conn: Connection, msg: protocol.JoinRequest) -> None:
        user = self._authenticate(conn, msg.token)
        added = self.db.add_member(msg.room, user)
        await self._ok(conn, "join")
        if added:
            logger.info("%s joined room %s", user, msg.room)
            await self._broadcast_event("join", msg.room, user)

    async def _on_leave(self, conn: Connection, msg: protocol.LeaveRequest) -> None:
        user = self._authenticate(conn, msg.token)
        if not self.db.remove_member(msg.room, user):
            await self._error(conn, ERR_FORBIDDEN)
            return
        await self._ok(conn, "leave")
        logger.info("%s left room %s", user, msg.room)
        await self._broadcast_event("leave", msg.room, user)

    async def _on_room_msg(self, conn: Connection, msg: protocol.RoomMsgRequest) -> None:
        user = self._authenticate(conn, msg.token)
        # Contrôle d'appartenance (OS5) : l'expéditeur ET chaque destinataire
        members = set(self.db.list_members(msg.room))
        if user not in members:
            logger.warning("room_msg refused: %s is not a member of %s", user, msg.room)
            await self._error(conn, ERR_FORBIDDEN)
            return
        if not set(msg.payloads) <= members:
            logger.warning("room_msg refused: recipients outside room %s", msg.room)
            await self._error(conn, ERR_FORBIDDEN)
            return
        delivered = 0
        for recipient, payload in msg.payloads.items():
            target = self.online.get(recipient)
            if recipient == user or target is None:
                continue
            delivery = protocol.RoomMsgDelivery(
                type="room_msg", room=msg.room, sender=user,
                payload=payload, nonce_ts=msg.nonce_ts,
            )
            delivered += await self._send(target, delivery)
        logger.info("room_msg from %s in %s delivered to %d", user, msg.room, delivered)
        await self._ok(conn, "room_msg")

    async def _on_dm(self, conn: Connection, msg: protocol.DmRequest) -> None:
        user = self._authenticate(conn, msg.token)
        target = self.online.get(msg.to)
        if target is None or msg.to == user:
            await self._error(conn, ERR_UNAVAILABLE)
            return
        delivery = protocol.DmDelivery(
            type="dm", sender=user, payload=msg.payload, nonce_ts=msg.nonce_ts
        )
        if not await self._send(target, delivery):
            await self._error(conn, ERR_UNAVAILABLE)
            return
        logger.info("dm from %s to %s", user, msg.to)
        await self._ok(conn, "dm")

    async def _on_users(self, conn: Connection, msg: protocol.UsersRequest) -> None:
        user = self._authenticate(conn, msg.token)
        members = self.db.list_members(msg.room)
        if user not in members:  # pas de liste pour un salon dont on n'est pas membre
            await self._error(conn, ERR_FORBIDDEN)
            return
        await self._ok(conn, "users", users=members)

    async def _on_get_pubkeys(self, conn: Connection, msg: protocol.GetPubkeysRequest) -> None:
        self._authenticate(conn, msg.token)
        await self._ok(conn, "get_pubkeys", pubkeys=self.db.get_pubkeys(msg.usernames))

    # --- Outils ---
    def _authenticate(self, conn: Connection, token: str) -> str:
        """Valide le jeton ET vérifie qu'il appartient à cette connexion."""
        username = self.auth.validate_token(token)
        if conn.username != username:
            # Jeton valide mais utilisé depuis une autre connexion : refusé
            logger.warning("token used from a foreign connection (%s)", conn.peer)
            raise AuthError(INVALID_SESSION)
        return username

    def _ip_blocked(self, peer: str) -> bool:
        """Limitation par IP : trop d'échecs de connexion sur la fenêtre glissante."""
        failures = self._ip_failures.get(peer)
        if not failures:
            return False
        cutoff = time.monotonic() - config.IP_WINDOW_SECONDS
        while failures and failures[0] < cutoff:
            failures.popleft()
        if not failures:
            del self._ip_failures[peer]
            return False
        return len(failures) >= config.IP_MAX_LOGIN_FAILURES

    def _unbind(self, conn: Connection) -> None:
        if conn.username and self.online.get(conn.username) is conn:
            del self.online[conn.username]
        conn.username = None

    async def _broadcast_event(self, event: str, room: str, username: str) -> None:
        msg = protocol.EventMessage(type="event", event=event, room=room, username=username)
        for member in self.db.list_members(room):
            target = self.online.get(member)
            if target is not None and member != username:
                await self._send(target, msg)

    async def _ok(self, conn: Connection, request: str, **fields) -> None:
        await self._send(conn, protocol.OkResponse(type="ok", request=request, **fields))

    async def _error(self, conn: Connection, message: str) -> None:
        await self._send(conn, protocol.ErrorMessage(type="error", message=message))

    async def _send(self, conn: Connection, msg) -> bool:
        """Envoie un message ; renvoie False si le client est injoignable."""
        try:
            data = protocol.encode(msg)
            async with conn.lock:
                conn.writer.write(data)
                await asyncio.wait_for(conn.writer.drain(), config.WRITE_TIMEOUT)
            return True
        except (ConnectionError, TimeoutError, ssl.SSLError, ProtocolError, RuntimeError):
            logger.info("could not send to %s", conn.peer)
            return False

    @staticmethod
    async def _close(conn: Connection) -> None:
        conn.writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(conn.writer.wait_closed(), 2)

    async def purge_loop(self, interval: float = 60) -> None:
        """Tâche de fond : supprime les sessions expirées."""
        while True:
            await asyncio.sleep(interval)
            purged = self.auth.purge_expired()
            if purged:
                logger.info("purged %d expired sessions", purged)


async def start_server(
    app: SecuChatServer, host: str, port: int, ssl_ctx: ssl.SSLContext
) -> asyncio.Server:
    """Démarre l'écoute TLS (port 0 = port libre choisi par l'OS)."""
    return await asyncio.start_server(
        app.handle_client,
        host,
        port,
        ssl=ssl_ctx,
        limit=config.MAX_MESSAGE_SIZE,
        ssl_handshake_timeout=config.HANDSHAKE_TIMEOUT,
    )


async def _serve(args: argparse.Namespace) -> None:
    db = Database(args.db)
    app = SecuChatServer(db, AuthService(db))
    ssl_ctx = make_server_ssl_context(args.cert, args.key)
    server = await start_server(app, args.host, args.port, ssl_ctx)
    purge = asyncio.create_task(app.purge_loop())
    logger.info("SecuChat server listening on %s:%d (TLS 1.3)", args.host, args.port)
    try:
        async with server:
            await server.serve_forever()
    finally:
        purge.cancel()
        db.close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Serveur SecuChat (TLS 1.3)")
    parser.add_argument("--host", default=config.DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT)
    parser.add_argument("--cert", default=str(config.DEFAULT_CERT))
    parser.add_argument("--key", default=str(config.DEFAULT_KEY))
    parser.add_argument("--db", default=str(config.DB_PATH))
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_serve(args))


if __name__ == "__main__":
    main()
