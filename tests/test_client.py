"""Tests du client : commandes, nettoyage d'affichage, E2E réel contre le serveur TLS."""

import asyncio
import json
import stat

import pytest
from nacl.pwhash import argon2id

from secuchat import crypto, protocol
from secuchat.client import ClientError, Incoming, SecuChatClient, parse_command, sanitize

PASSWORD = "correct horse battery staple"
FAST_KDF = {"kdf_opslimit": argon2id.OPSLIMIT_MIN, "kdf_memlimit": argon2id.MEMLIMIT_MIN}


# --- Fonctions pures ---
@pytest.mark.parametrize(
    "line,expected",
    [
        ("/login alice", ("login", ["alice"])),
        ("/msg projet salut tout le monde", ("msg", ["projet", "salut tout le monde"])),
        ("/dm bob  hello  you", ("dm", ["bob", "hello  you"])),
        ("/QUIT", ("quit", [])),
        ("/", ("", [])),
        ("hello", ("", ["hello"])),
        ("", ("", [])),
    ],
)
def test_parse_command(line, expected):
    assert parse_command(line) == expected


def test_sanitize_removes_terminal_escapes():
    evil = "hi\x1b[2J\x1b]0;pwned\x07\r\nfake line‮"
    clean = sanitize(evil)
    assert "\x1b" not in clean and "\r" not in clean and "\n" not in clean
    assert "‮" not in clean  # inversion de texte (RTL override)
    assert sanitize("salut 👋 é") == "salut 👋 é"


# --- Bout en bout avec le vrai serveur ---
@pytest.fixture
async def make_client(running_server, tls_cert, tmp_path):
    _, port = running_server
    clients = []

    async def _make(name, register=True, login=True):
        inbox: asyncio.Queue = asyncio.Queue()
        client = SecuChatClient(keys_dir=tmp_path / "keys", on_incoming=inbox.put_nowait,
                                **FAST_KDF)
        client.inbox = inbox
        await client.connect("127.0.0.1", port, tls_cert[0], server_hostname="localhost")
        clients.append(client)
        if register:
            await client.register(name, PASSWORD)
        if login:
            await client.login(name, PASSWORD)
        return client

    yield _make
    for client in clients:
        await client.close()


async def next_item(client, kind=None, timeout=2.0) -> Incoming:
    while True:
        item = await asyncio.wait_for(client.inbox.get(), timeout)
        if kind is None or item.kind == kind:
            return item


async def test_register_saves_encrypted_key(make_client, tmp_path):
    await make_client("alice", login=False)
    path = tmp_path / "keys" / "alice.key"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert crypto.load_private_key(PASSWORD, path)


async def test_register_refuses_weak_password_and_existing_key(make_client):
    alice = await make_client("alice", login=False)
    with pytest.raises(ClientError):
        await alice.register("bob", "short")
    with pytest.raises(ClientError):
        await alice.register("alice", PASSWORD)  # la clé existe déjà


async def test_failed_register_removes_key(make_client, tmp_path):
    await make_client("alice", login=False)
    other = await make_client("x", register=False, login=False)
    (tmp_path / "keys" / "alice.key").unlink()
    with pytest.raises(ClientError):
        await other.register("alice", PASSWORD)  # refusé par le serveur : déjà pris
    assert not (tmp_path / "keys" / "alice.key").exists()


async def test_login_wrong_password(make_client):
    alice = await make_client("alice", login=False)
    with pytest.raises(ClientError):
        await alice.login("alice", "wrong password!!")


async def test_commands_require_login(make_client):
    alice = await make_client("alice", login=False)
    with pytest.raises(ClientError, match="not logged in"):
        await alice.join("projet")


async def test_room_message_end_to_end(make_client):
    alice = await make_client("alice")
    bob = await make_client("bob")
    await alice.join("projet")
    await bob.join("projet")
    event = await next_item(alice, "event")
    assert event.sender == "bob"

    assert await alice.send_room("projet", "salut l'équipe 🔐") == 1
    item = await next_item(bob, "room")
    assert (item.sender, item.room, item.text) == ("alice", "projet", "salut l'équipe 🔐")


async def test_dm_end_to_end(make_client):
    alice = await make_client("alice")
    bob = await make_client("bob")
    await alice.send_dm("bob", "coucou")
    item = await next_item(bob, "dm")
    assert (item.sender, item.text) == ("alice", "coucou")
    with pytest.raises(ClientError):
        await alice.send_dm("ghost", "hello?")


async def test_alone_in_room(make_client):
    alice = await make_client("alice")
    await alice.join("solo")
    with pytest.raises(ClientError, match="no other member"):
        await alice.send_room("solo", "anyone?")


# --- Vérification de l'enveloppe chiffrée (serveur malveillant) ---
async def _forge(sender_client, recipient, text, ts, ctx):
    keys = await sender_client._get_pubkeys([recipient])
    plaintext = json.dumps({"v": 1, "ts": ts, "ctx": ctx, "text": text})
    return crypto.encrypt_for(keys[recipient], sender_client._private_key, plaintext)


async def test_server_cannot_move_message_to_other_room(make_client):
    alice = await make_client("alice")
    bob = await make_client("bob")
    ts = 1_794_950_000
    alice._clock = bob._clock = lambda: ts
    payload = await _forge(alice, "bob", "secret", ts, "room:privé")
    forged = protocol.RoomMsgDelivery(type="room_msg", room="public", sender="alice",
                                      payload=payload, nonce_ts=ts)
    with pytest.raises(ClientError, match="integrity"):
        await bob._handle_push(forged)


async def test_replay_and_old_messages_rejected(make_client):
    alice = await make_client("alice")
    bob = await make_client("bob")
    now = 1_794_950_000
    bob._clock = lambda: now
    payload = await _forge(alice, "bob", "hi", now, "dm")
    msg = protocol.DmDelivery(type="dm", sender="alice", payload=payload, nonce_ts=now)
    assert (await bob._handle_push(msg)).text == "hi"
    with pytest.raises(ClientError, match="replayed"):
        await bob._handle_push(msg)

    old = await _forge(alice, "bob", "old", now - 3600, "dm")
    msg = protocol.DmDelivery(type="dm", sender="alice", payload=old, nonce_ts=now - 3600)
    with pytest.raises(ClientError, match="too old"):
        await bob._handle_push(msg)


async def test_timestamp_rewritten_by_server_rejected(make_client):
    alice = await make_client("alice")
    bob = await make_client("bob")
    now = 1_794_950_000
    bob._clock = lambda: now
    payload = await _forge(alice, "bob", "hi", now - 3600, "dm")  # vieux message...
    msg = protocol.DmDelivery(type="dm", sender="alice", payload=payload, nonce_ts=now)
    with pytest.raises(ClientError, match="integrity"):  # ...présenté comme récent
        await bob._handle_push(msg)


async def test_untrusted_server_certificate(running_server, other_cert, tmp_path):
    """MITM : le client n'accepte que le certificat donné par --ca."""
    _, port = running_server
    client = SecuChatClient(keys_dir=tmp_path)
    with pytest.raises(ClientError, match="verification failed"):
        await client.connect("127.0.0.1", port, other_cert[0], server_hostname="localhost")


async def test_wrong_hostname_refused(running_server, tls_cert, tmp_path):
    _, port = running_server
    client = SecuChatClient(keys_dir=tmp_path)
    with pytest.raises(ClientError, match="verification failed"):
        await client.connect("127.0.0.1", port, tls_cert[0], server_hostname="evil.example")


async def test_invalid_ca_file(tmp_path):
    bad = tmp_path / "bad.crt"
    bad.write_text("not a certificate")
    with pytest.raises(ClientError, match="cannot load CA"):
        await SecuChatClient(keys_dir=tmp_path).connect("127.0.0.1", 1, bad)
