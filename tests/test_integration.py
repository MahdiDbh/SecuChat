"""Test d'intégration : serveur TLS réel + 3 vrais clients SecuChat.

Scénario (CLAUDE.md §8) : alice et bob sont dans #projet, carol non.
- un message de salon arrive à bob et pas à carol ;
- carol ne peut pas écrire dans #projet ;
- le serveur ne voit jamais le texte en clair.
"""

import asyncio

import pytest
from nacl.pwhash import argon2id

from secuchat.client import ClientError, SecuChatClient

PASSWORD = "correct horse battery staple"
FAST_KDF = {"kdf_opslimit": argon2id.OPSLIMIT_MIN, "kdf_memlimit": argon2id.MEMLIMIT_MIN}
SECRET_TEXT = "rendez-vous 18h salle 42 : code porte 7391"


@pytest.fixture
async def trio(running_server, tls_cert, tmp_path):
    """alice et bob dans #projet, carol connectée mais hors du salon."""
    app, port = running_server

    # On enregistre tout ce que le serveur reçoit, pour vérifier qu'il ne voit que du chiffré
    received: list[bytes] = []
    original_dispatch = app.dispatch

    async def recording_dispatch(conn, line):
        received.append(line)
        await original_dispatch(conn, line)

    app.dispatch = recording_dispatch

    clients = {}
    for name in ("alice", "bob", "carol"):
        inbox: asyncio.Queue = asyncio.Queue()
        client = SecuChatClient(keys_dir=tmp_path / name, on_incoming=inbox.put_nowait,
                                **FAST_KDF)
        client.inbox = inbox
        await client.connect("127.0.0.1", port, tls_cert[0], server_hostname="localhost")
        await client.register(name, PASSWORD)
        await client.login(name, PASSWORD)
        clients[name] = client

    await clients["alice"].join("projet")
    await clients["bob"].join("projet")
    await next_item(clients["alice"], "event")  # "bob joined #projet"

    try:
        yield clients, received
    finally:
        for client in clients.values():
            await client.close()


async def next_item(client, kind, timeout=2.0):
    while True:
        item = await asyncio.wait_for(client.inbox.get(), timeout)
        if item.kind == kind:
            return item


async def assert_nothing_received(client, timeout=0.3):
    with pytest.raises(TimeoutError):
        await next_item(client, "room", timeout)


async def test_room_message_reaches_members_only(trio):
    clients, _ = trio
    alice, bob, carol = clients["alice"], clients["bob"], clients["carol"]

    assert await alice.send_room("projet", SECRET_TEXT) == 1

    item = await next_item(bob, "room")
    assert (item.sender, item.room, item.text) == ("alice", "projet", SECRET_TEXT)
    await assert_nothing_received(carol)


async def test_non_member_cannot_send(trio):
    clients, _ = trio
    carol, alice, bob = clients["carol"], clients["alice"], clients["bob"]

    with pytest.raises(ClientError, match="forbidden"):
        await carol.send_room("projet", "je m'incruste")
    with pytest.raises(ClientError, match="forbidden"):
        await carol.users("projet")
    await assert_nothing_received(alice)
    await assert_nothing_received(bob)


async def test_server_never_sees_plaintext(trio):
    clients, received = trio
    alice, bob = clients["alice"], clients["bob"]

    await alice.send_room("projet", SECRET_TEXT)
    await bob.send_dm("alice", SECRET_TEXT)
    await next_item(bob, "room")
    await next_item(alice, "dm")

    raw = b"".join(received)
    assert b'"room_msg"' in raw and b'"dm"' in raw  # les messages sont bien passés...
    assert SECRET_TEXT.encode() not in raw  # ...mais jamais en clair
    assert b"7391" not in raw


async def test_member_who_left_no_longer_receives(trio):
    clients, _ = trio
    alice, bob = clients["alice"], clients["bob"]

    await bob.leave("projet")
    event = await next_item(alice, "event")
    assert event.text == "bob left #projet"

    with pytest.raises(ClientError, match="no other member"):
        await alice.send_room("projet", "il y a quelqu'un ?")
    with pytest.raises(ClientError, match="forbidden"):
        await bob.send_room("projet", "je suis parti")


async def test_carol_joins_and_then_receives(trio):
    clients, _ = trio
    alice, bob, carol = clients["alice"], clients["bob"], clients["carol"]

    await carol.join("projet")
    assert await alice.send_room("projet", "bienvenue carol") == 2
    for member in (bob, carol):
        item = await next_item(member, "room")
        assert item.text == "bienvenue carol"
