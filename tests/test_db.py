"""Tests de db.py : utilisateurs, salons, injection SQL, permissions du fichier."""

import stat

import pytest

from secuchat.db import Database, UserExistsError

PUBKEY = "A" * 43 + "="


@pytest.fixture
def db():
    with Database() as database:
        database.create_user("alice", "hash-a", PUBKEY)
        database.create_user("bob", "hash-b", PUBKEY)
        yield database


def test_create_and_get_user(db):
    user = db.get_user("alice")
    assert user.username == "alice"
    assert user.pwd_hash == "hash-a"
    assert user.failed_attempts == 0
    assert user.locked_until == 0


def test_duplicate_username_rejected(db):
    with pytest.raises(UserExistsError):
        db.create_user("alice", "other", PUBKEY)


def test_unknown_user(db):
    assert db.get_user("nobody") is None


@pytest.mark.parametrize(
    "payload",
    ["' OR '1'='1", "alice' --", "alice'; DROP TABLE users; --", '" OR ""="'],
)
def test_sql_injection_is_inert(db, payload):
    assert db.get_user(payload) is None
    assert db.get_pubkeys([payload]) == {}
    assert not db.is_member("room", payload)
    # La table est toujours là et intacte
    assert db.get_user("alice") is not None


def test_injection_string_stored_literally(db):
    weird = "x'); DROP TABLE users; --"
    db.create_user(weird, "h", PUBKEY)
    assert db.get_user(weird).username == weird
    assert db.get_user("bob") is not None


def test_update_login_state(db):
    user = db.get_user("alice")
    db.update_login_state(user.id, 3, 1234.5)
    user = db.get_user("alice")
    assert user.failed_attempts == 3
    assert user.locked_until == 1234.5


def test_update_password_hash(db):
    user = db.get_user("alice")
    db.update_password_hash(user.id, "new-hash")
    assert db.get_user("alice").pwd_hash == "new-hash"


def test_get_pubkeys(db):
    assert db.get_pubkeys(["alice", "bob", "nobody"]) == {"alice": PUBKEY, "bob": PUBKEY}


def test_room_membership(db):
    assert db.add_member("projet", "alice") is True
    assert db.add_member("projet", "alice") is False  # déjà membre
    assert db.add_member("projet", "bob") is True
    assert db.is_member("projet", "alice")
    assert db.list_members("projet") == ["alice", "bob"]
    assert db.rooms_of("alice") == ["projet"]

    assert db.remove_member("projet", "alice") is True
    assert db.remove_member("projet", "alice") is False
    assert not db.is_member("projet", "alice")
    assert db.list_members("projet") == ["bob"]


def test_unknown_user_cannot_join(db):
    assert db.add_member("projet", "ghost") is False
    assert db.list_members("projet") == []


def test_unknown_room(db):
    assert db.list_members("nope") == []
    assert not db.is_member("nope", "alice")


def test_file_permissions_and_persistence(tmp_path):
    path = tmp_path / "data" / "server.db"
    with Database(path) as database:
        database.create_user("alice", "h", PUBKEY)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    with Database(path) as database:
        assert database.get_user("alice") is not None
