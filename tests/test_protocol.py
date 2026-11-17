"""Tests du protocole : messages valides acceptés, messages invalides rejetés."""

import base64
import json

import pytest

from secuchat import config, protocol
from secuchat.protocol import ProtocolError, decode_client, decode_server

TOKEN = "A" * 43
PUBKEY = base64.b64encode(b"\x01" * 32).decode()
PAYLOAD = base64.b64encode(b"ciphertext").decode()
PASSWORD = "correct horse battery"


def line(**fields) -> bytes:
    return json.dumps(fields).encode() + b"\n"


VALID_CLIENT = [
    {"type": "register", "username": "alice", "password": PASSWORD, "pubkey": PUBKEY},
    {"type": "login", "username": "alice", "password": PASSWORD},
    {"type": "logout", "token": TOKEN},
    {"type": "join", "token": TOKEN, "room": "projet"},
    {"type": "leave", "token": TOKEN, "room": "projet"},
    {
        "type": "room_msg",
        "token": TOKEN,
        "room": "projet",
        "payloads": {"alice": PAYLOAD, "bob": PAYLOAD},
        "nonce_ts": 1794950000,
    },
    {"type": "dm", "token": TOKEN, "to": "bob", "payload": PAYLOAD, "nonce_ts": 1794950000},
    {"type": "users", "token": TOKEN, "room": "projet"},
    {"type": "get_pubkeys", "token": TOKEN, "usernames": ["alice", "bob"]},
]


@pytest.mark.parametrize("fields", VALID_CLIENT, ids=lambda f: f["type"])
def test_valid_client_messages(fields):
    msg = decode_client(line(**fields))
    assert msg.type == fields["type"]


@pytest.mark.parametrize("fields", VALID_CLIENT, ids=lambda f: f["type"])
def test_roundtrip(fields):
    msg = decode_client(line(**fields))
    encoded = protocol.encode(msg)
    assert encoded.endswith(b"\n") and encoded.count(b"\n") == 1
    assert decode_client(encoded) == msg


def test_valid_server_messages():
    assert decode_server(line(type="ok", request="login", token=TOKEN)).token == TOKEN
    assert decode_server(line(type="error", message="invalid request")).type == "error"
    ev = decode_server(line(type="event", event="join", room="projet", username="bob"))
    assert ev.event == "join"
    msg = decode_server(
        line(type="room_msg", room="projet", sender="bob", payload=PAYLOAD, nonce_ts=1)
    )
    assert msg.sender == "bob"
    assert decode_server(line(type="dm", sender="bob", payload=PAYLOAD, nonce_ts=1)).type == "dm"


@pytest.mark.parametrize(
    "username", ["ab", "a" * 33, "alice' OR '1'='1", "bob\n", "élise", "a b", ""]
)
def test_invalid_username_rejected(username):
    with pytest.raises(ProtocolError):
        decode_client(line(type="login", username=username, password=PASSWORD))


def test_missing_field_rejected():
    with pytest.raises(ProtocolError):
        decode_client(line(type="login", username="alice"))


def test_message_too_long_rejected():
    big = "A" * (config.MAX_MESSAGE_SIZE + 4)
    with pytest.raises(ProtocolError):
        decode_client(line(type="dm", token=TOKEN, to="bob", payload=big, nonce_ts=1))


def test_encode_too_large_rejected():
    payload = "A" * (config.MAX_MESSAGE_SIZE - 10)
    msg = protocol.DmRequest(type="dm", token=TOKEN, to="bob", payload=payload, nonce_ts=1)
    with pytest.raises(ProtocolError):
        protocol.encode(msg)


@pytest.mark.parametrize(
    "raw",
    [
        b"not json\n",
        b"[]\n",
        b"\xff\xfe\n",
        line(type="unknown"),
        line(username="alice", password=PASSWORD),  # pas de type
        line(type="login", username="alice", password=PASSWORD, admin=True),  # champ en trop
        line(type="login", username="alice", password="short"),  # mot de passe trop court
        line(type="join", token="bad", room="projet"),  # jeton mal formé
        line(type="join", token=TOKEN, room="salon#1"),
        line(type="dm", token=TOKEN, to="bob", payload=PAYLOAD, nonce_ts="1"),  # pas de coercion
        line(type="dm", token=TOKEN, to="bob", payload="<script>", nonce_ts=1),
        line(type="room_msg", token=TOKEN, room="p", payloads={}, nonce_ts=1),
        line(type="error", message="x"),  # un client n'envoie pas d'error
    ],
)
def test_invalid_messages_rejected(raw):
    with pytest.raises(ProtocolError):
        decode_client(raw)


def test_error_does_not_leak_input():
    """L'exception ne doit contenir ni le mot de passe ni l'erreur pydantic d'origine."""
    secret = "my-very-secret-password"
    with pytest.raises(ProtocolError) as exc:
        decode_client(line(type="login", username="a!", password=secret))
    assert secret not in str(exc.value)
    assert exc.value.__cause__ is None
    assert exc.value.__suppress_context__
