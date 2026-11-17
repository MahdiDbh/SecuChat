"""Tests du serveur via de vraies connexions TLS (client JSON minimal)."""

import asyncio
import base64
import json
import logging
import ssl

import pytest

from secuchat import config, protocol

PASSWORD = "correct horse battery staple"
PUBKEY = base64.b64encode(b"\x09" * 32).decode()
PAYLOAD_BOB = base64.b64encode(b"cipher-for-bob").decode()
PAYLOAD_ALICE = base64.b64encode(b"cipher-for-alice").decode()


class Peer:
    """Client de test : envoie des dicts JSON, valide les réponses avec decode_server."""

    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.inbox: list = []  # messages poussés (event, room_msg, dm) reçus entre-temps
        self.token = None

    async def send_raw(self, data: bytes):
        self.writer.write(data)
        await self.writer.drain()

    async def recv(self, timeout=2.0):
        line = await asyncio.wait_for(self.reader.readline(), timeout)
        if not line:
            raise ConnectionError("closed")
        return protocol.decode_server(line)

    async def call(self, **msg):
        """Envoie une requête et renvoie la réponse ok/error."""
        await self.send_raw(json.dumps(msg).encode() + b"\n")
        while True:
            reply = await self.recv()
            if reply.type in ("ok", "error"):
                return reply
            self.inbox.append(reply)

    async def push(self, timeout=2.0):
        return self.inbox.pop(0) if self.inbox else await self.recv(timeout)

    async def assert_silent(self, timeout=0.3):
        assert not self.inbox
        with pytest.raises(TimeoutError):
            await self.recv(timeout)

    async def signup(self, name):
        assert (await self.call(type="register", username=name, password=PASSWORD,
                                pubkey=PUBKEY)).type == "ok"
        reply = await self.call(type="login", username=name, password=PASSWORD)
        assert reply.type == "ok"
        self.token = reply.token
        return self

    async def close(self):
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


@pytest.fixture
async def connect(running_server, client_ssl):
    _, port = running_server
    peers = []

    async def _connect():
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_ssl, server_hostname="localhost",
            limit=config.MAX_MESSAGE_SIZE * 2,
        )
        peer = Peer(reader, writer)
        peers.append(peer)
        return peer

    yield _connect
    for peer in peers:
        await peer.close()


# --- TLS ---
async def test_tls12_client_refused(running_server, tls_cert):
    _, port = running_server
    ctx = ssl.create_default_context(cafile=str(tls_cert[0]))
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises((ssl.SSLError, ConnectionError)):
        await asyncio.open_connection("127.0.0.1", port, ssl=ctx, server_hostname="localhost")


async def test_untrusted_certificate_refused_by_client(running_server):
    _, port = running_server
    ctx = ssl.create_default_context()  # CA système : ne connaît pas notre certificat
    with pytest.raises(ssl.SSLCertVerificationError):
        await asyncio.open_connection("127.0.0.1", port, ssl=ctx, server_hostname="localhost")


# --- Validation des entrées ---
async def test_invalid_message_gets_generic_error_and_connection_stays(connect):
    peer = await connect()
    await peer.send_raw(b"{not json}\n")
    reply = await peer.recv()
    assert reply.type == "error" and reply.message == "invalid request"
    assert (await peer.call(type="register", username="alice", password=PASSWORD,
                            pubkey=PUBKEY)).type == "ok"


async def test_oversized_line_closes_connection(connect):
    peer = await connect()
    await peer.send_raw(b"A" * (config.MAX_MESSAGE_SIZE + 10) + b"\n")
    reply = await peer.recv()
    assert reply.type == "error" and reply.message == "message too large"
    with pytest.raises(ConnectionError):
        await peer.recv()


async def test_read_timeout_closes_idle_connection(running_server, connect):
    app, _ = running_server
    app.read_timeout = 0.2
    peer = await connect()
    with pytest.raises(ConnectionError):
        await peer.recv(timeout=2)


# --- Authentification ---
async def test_register_login_and_generic_errors(connect):
    peer = await connect()
    await peer.signup("alice")
    assert len(peer.token) == 43
    wrong = await peer.call(type="login", username="alice", password="wrong password!!")
    unknown = await peer.call(type="login", username="nobody", password=PASSWORD)
    assert wrong.type == unknown.type == "error"
    assert wrong.message == unknown.message == "invalid credentials"


async def test_requires_valid_token(connect):
    peer = await connect()
    reply = await peer.call(type="join", token="A" * 43, room="projet")
    assert reply.type == "error" and reply.message == "invalid session"


async def test_token_bound_to_its_connection(connect):
    alice = await (await connect()).signup("alice")
    bob = await (await connect()).signup("bob")
    reply = await bob.call(type="join", token=alice.token, room="projet")
    assert reply.type == "error" and reply.message == "invalid session"


async def test_logout_invalidates_token(connect):
    alice = await (await connect()).signup("alice")
    assert (await alice.call(type="logout", token=alice.token)).type == "ok"
    reply = await alice.call(type="join", token=alice.token, room="projet")
    assert reply.type == "error"


async def test_ip_rate_limit(running_server, connect, monkeypatch):
    monkeypatch.setattr(config, "IP_MAX_LOGIN_FAILURES", 3)
    peer = await connect()
    await peer.signup("alice")
    for _ in range(3):
        await peer.call(type="login", username="nobody", password=PASSWORD)
    # Même avec le bon mot de passe, l'IP est temporairement bloquée
    reply = await peer.call(type="login", username="alice", password=PASSWORD)
    assert reply.type == "error" and reply.message == "invalid credentials"


# --- Salons ---
async def test_room_message_reaches_members_only(connect):
    alice = await (await connect()).signup("alice")
    bob = await (await connect()).signup("bob")
    carol = await (await connect()).signup("carol")

    assert (await alice.call(type="join", token=alice.token, room="projet")).type == "ok"
    assert (await bob.call(type="join", token=bob.token, room="projet")).type == "ok"
    event = await alice.push()
    assert (event.type, event.event, event.username) == ("event", "join", "bob")

    reply = await alice.call(
        type="room_msg", token=alice.token, room="projet",
        payloads={"alice": PAYLOAD_ALICE, "bob": PAYLOAD_BOB}, nonce_ts=1794950000,
    )
    assert reply.type == "ok"
    msg = await bob.push()
    assert (msg.type, msg.room, msg.sender, msg.payload) == (
        "room_msg", "projet", "alice", PAYLOAD_BOB,  # bob ne reçoit que SON chiffré
    )
    await carol.assert_silent()
    await alice.assert_silent()  # pas d'écho à l'expéditeur


async def test_non_member_cannot_send_or_list(connect):
    alice = await (await connect()).signup("alice")
    carol = await (await connect()).signup("carol")
    await alice.call(type="join", token=alice.token, room="projet")

    reply = await carol.call(type="room_msg", token=carol.token, room="projet",
                             payloads={"alice": PAYLOAD_ALICE}, nonce_ts=1)
    assert reply.type == "error" and reply.message == "forbidden"
    assert (await carol.call(type="users", token=carol.token, room="projet")).type == "error"
    await alice.assert_silent()


async def test_recipient_outside_room_refused(connect):
    alice = await (await connect()).signup("alice")
    carol = await (await connect()).signup("carol")
    await alice.call(type="join", token=alice.token, room="projet")
    reply = await alice.call(type="room_msg", token=alice.token, room="projet",
                             payloads={"carol": PAYLOAD_BOB}, nonce_ts=1)
    assert reply.type == "error" and reply.message == "forbidden"
    await carol.assert_silent()


async def test_users_and_leave_event(connect):
    alice = await (await connect()).signup("alice")
    bob = await (await connect()).signup("bob")
    await alice.call(type="join", token=alice.token, room="projet")
    await bob.call(type="join", token=bob.token, room="projet")
    await alice.push()  # event join de bob

    users = await alice.call(type="users", token=alice.token, room="projet")
    assert users.users == ["alice", "bob"]

    assert (await bob.call(type="leave", token=bob.token, room="projet")).type == "ok"
    event = await alice.push()
    assert (event.event, event.username) == ("leave", "bob")
    # Quitter un salon dont on n'est pas membre
    assert (await bob.call(type="leave", token=bob.token, room="projet")).type == "error"


# --- Messages directs et clés ---
async def test_dm_and_pubkeys(connect):
    alice = await (await connect()).signup("alice")
    bob = await (await connect()).signup("bob")

    keys = await alice.call(type="get_pubkeys", token=alice.token, usernames=["bob", "ghost"])
    assert keys.pubkeys == {"bob": PUBKEY}

    reply = await alice.call(type="dm", token=alice.token, to="bob", payload=PAYLOAD_BOB,
                             nonce_ts=1)
    assert reply.type == "ok"
    msg = await bob.push()
    assert (msg.type, msg.sender, msg.payload) == ("dm", "alice", PAYLOAD_BOB)

    offline = await alice.call(type="dm", token=alice.token, to="ghost", payload=PAYLOAD_BOB,
                               nonce_ts=1)
    assert offline.type == "error" and offline.message == "recipient unavailable"


# --- Journalisation ---
async def test_logs_never_contain_secrets(connect, caplog):
    caplog.set_level(logging.DEBUG)
    alice = await (await connect()).signup("alice")
    bob = await (await connect()).signup("bob")
    await alice.call(type="join", token=alice.token, room="projet")
    await bob.call(type="join", token=bob.token, room="projet")
    await alice.call(type="room_msg", token=alice.token, room="projet",
                     payloads={"bob": PAYLOAD_BOB}, nonce_ts=1)
    await alice.call(type="login", username="alice", password="wrong password!!")
    logs = caplog.text
    assert "alice" in logs  # les événements sont bien journalisés...
    for secret in (PASSWORD, "wrong password!!", alice.token, bob.token, PAYLOAD_BOB):
        assert secret not in logs  # ...mais jamais les secrets
