"""Tests de crypto.py : chiffrement E2E et stockage chiffré de la clé privée."""

import base64
import json
import os
import stat

import pytest
from nacl.pwhash import argon2id

from secuchat import crypto, protocol
from secuchat.crypto import CryptoError

PASSWORD = "correct horse battery staple"
# Paramètres KDF rapides pour les tests (le défaut est MODERATE)
FAST = {"opslimit": argon2id.OPSLIMIT_MIN, "memlimit": argon2id.MEMLIMIT_MIN}


@pytest.fixture
def alice():
    return crypto.generate_keypair()


@pytest.fixture
def bob():
    return crypto.generate_keypair()


def flip_byte(payload: str, index: int = -1) -> str:
    data = bytearray(base64.b64decode(payload))
    data[index] ^= 0x01
    return base64.b64encode(bytes(data)).decode()


# --- Messages ---
def test_roundtrip(alice, bob):
    payload = crypto.encrypt_for(crypto.public_key_b64(bob), alice, "salut bob 👋")
    assert crypto.decrypt_from(alice.public_key, bob, payload) == "salut bob 👋"


def test_payload_is_not_plaintext_and_fits_protocol(alice, bob):
    payload = crypto.encrypt_for(bob.public_key, alice, "secret message")
    assert "secret" not in payload
    assert b"secret" not in base64.b64decode(payload)
    # Accepté tel quel par le schéma du protocole
    protocol.DmDelivery(type="dm", sender="alice", payload=payload, nonce_ts=1)


def test_random_nonce_each_time(alice, bob):
    a = crypto.encrypt_for(bob.public_key, alice, "same")
    b = crypto.encrypt_for(bob.public_key, alice, "same")
    assert a != b


@pytest.mark.parametrize("index", [0, 30, -1])  # nonce, chiffré, tag
def test_tampered_message_rejected(alice, bob, index):
    payload = crypto.encrypt_for(bob.public_key, alice, "pay 10 euros")
    with pytest.raises(CryptoError):
        crypto.decrypt_from(alice.public_key, bob, flip_byte(payload, index))


def test_truncated_or_garbage_rejected(alice, bob):
    payload = crypto.encrypt_for(bob.public_key, alice, "hello")
    for bad in [payload[:20], "not base64 !!", "", base64.b64encode(b"x" * 10).decode()]:
        with pytest.raises(CryptoError):
            crypto.decrypt_from(alice.public_key, bob, bad)


def test_wrong_recipient_cannot_decrypt(alice, bob):
    eve = crypto.generate_keypair()
    payload = crypto.encrypt_for(bob.public_key, alice, "for bob only")
    with pytest.raises(CryptoError):
        crypto.decrypt_from(alice.public_key, eve, payload)


def test_wrong_sender_detected(alice, bob):
    """Authenticité : un message n'est accepté que de l'expéditeur annoncé."""
    mallory = crypto.generate_keypair()
    payload = crypto.encrypt_for(bob.public_key, mallory, "I am alice")
    with pytest.raises(CryptoError):
        crypto.decrypt_from(alice.public_key, bob, payload)


@pytest.mark.parametrize("value", ["", "abc", "!!!", base64.b64encode(b"x" * 31).decode()])
def test_invalid_public_key(value):
    with pytest.raises(CryptoError):
        crypto.load_public_key(value)


def test_public_key_b64_format(alice):
    value = crypto.public_key_b64(alice)
    assert len(value) == 44
    assert bytes(crypto.load_public_key(value)) == bytes(alice.public_key)


# --- Stockage de la clé privée ---
def test_save_and_load_private_key(tmp_path, alice):
    path = tmp_path / "keys" / "alice.key"
    crypto.save_private_key(alice, PASSWORD, path, **FAST)
    loaded = crypto.load_private_key(PASSWORD, path)
    assert bytes(loaded) == bytes(alice)


def test_key_file_is_encrypted_and_600(tmp_path, alice):
    path = tmp_path / "keys" / "alice.key"
    crypto.save_private_key(alice, PASSWORD, path, **FAST)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    raw = path.read_bytes()
    assert bytes(alice) not in raw
    assert base64.b64encode(bytes(alice)) not in raw
    assert PASSWORD.encode() not in raw
    assert list(tmp_path.joinpath("keys").iterdir()) == [path]  # pas de fichier temporaire


def test_wrong_password_rejected(tmp_path, alice):
    path = tmp_path / "alice.key"
    crypto.save_private_key(alice, PASSWORD, path, **FAST)
    with pytest.raises(CryptoError):
        crypto.load_private_key("wrong password!!", path)


def test_loose_permissions_refused(tmp_path, alice):
    path = tmp_path / "alice.key"
    crypto.save_private_key(alice, PASSWORD, path, **FAST)
    os.chmod(path, 0o644)
    with pytest.raises(CryptoError):
        crypto.load_private_key(PASSWORD, path)


def test_tampered_key_file_rejected(tmp_path, alice):
    path = tmp_path / "alice.key"
    crypto.save_private_key(alice, PASSWORD, path, **FAST)
    doc = json.loads(path.read_bytes())
    doc["data"] = flip_byte(doc["data"])
    path.write_text(json.dumps(doc))
    with pytest.raises(CryptoError):
        crypto.load_private_key(PASSWORD, path)


@pytest.mark.parametrize(
    "change",
    [
        {"memlimit": 64 * 1024**3},  # 64 Go : refusé avant de lancer la KDF
        {"opslimit": 10**9},
        {"version": 99},
        {"kdf": "md5"},
        {"salt": "!!"},
    ],
)
def test_malicious_key_file_rejected(tmp_path, alice, change):
    path = tmp_path / "alice.key"
    crypto.save_private_key(alice, PASSWORD, path, **FAST)
    doc = json.loads(path.read_bytes())
    doc.update(change)
    path.write_text(json.dumps(doc))
    with pytest.raises(CryptoError):
        crypto.load_private_key(PASSWORD, path)


def test_missing_or_corrupt_file(tmp_path):
    with pytest.raises(CryptoError):
        crypto.load_private_key(PASSWORD, tmp_path / "nope.key")
    bad = tmp_path / "bad.key"
    bad.write_text("not json")
    os.chmod(bad, 0o600)
    with pytest.raises(CryptoError):
        crypto.load_private_key(PASSWORD, bad)


def test_key_path_for(tmp_path):
    assert crypto.key_path_for("alice", tmp_path) == tmp_path / "alice.key"
    for bad in ["../etc/passwd", "a/b", "..", ""]:
        with pytest.raises(CryptoError):
            crypto.key_path_for(bad, tmp_path)
