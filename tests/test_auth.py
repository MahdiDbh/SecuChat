"""Tests de auth.py : inscription, connexion, brute-force, jetons, injection SQL."""

import base64

import pytest
from argon2 import PasswordHasher

from secuchat import config
from secuchat.auth import (
    INVALID_CREDENTIALS,
    INVALID_SESSION,
    AuthError,
    AuthService,
)
from secuchat.db import Database

PASSWORD = "correct horse battery staple"
PUBKEY = base64.b64encode(b"\x07" * 32).decode()
# Paramètres Argon2 réduits pour que les tests restent rapides
FAST_HASHER = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


class FakeClock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def db():
    with Database() as database:
        yield database


@pytest.fixture
def auth(db, clock):
    service = AuthService(db, hasher=FAST_HASHER, clock=clock)
    service.register("alice", PASSWORD, PUBKEY)
    return service


# --- Inscription ---
def test_register_stores_argon2id_hash_not_password(db):
    AuthService(db).register("bob", PASSWORD, PUBKEY)  # hasher par défaut
    user = db.get_user("bob")
    assert user.pwd_hash.startswith("$argon2id$")
    assert PASSWORD not in user.pwd_hash
    assert user.pubkey == PUBKEY


def test_register_duplicate_refused(auth):
    with pytest.raises(AuthError):
        auth.register("alice", PASSWORD, PUBKEY)


@pytest.mark.parametrize(
    "username,password,pubkey",
    [
        ("ab", PASSWORD, PUBKEY),  # identifiant trop court
        ("alice'--", PASSWORD, PUBKEY),  # caractères interdits
        ("carol", "short", PUBKEY),  # mot de passe < 12
        ("carol", "x" * 129, PUBKEY),  # mot de passe > 128
        ("carol", PASSWORD, "not-base64!"),
        ("carol", PASSWORD, base64.b64encode(b"\x00" * 16).decode()),  # mauvaise taille
    ],
)
def test_register_invalid_input_refused(auth, username, password, pubkey):
    with pytest.raises(AuthError):
        auth.register(username, password, pubkey)


# --- Connexion ---
def test_login_ok_returns_token(auth):
    token = auth.login("alice", PASSWORD)
    assert len(token) == 43  # 32 octets en base64url
    assert auth.validate_token(token) == "alice"


def test_wrong_password_and_unknown_user_same_error(auth):
    with pytest.raises(AuthError) as wrong:
        auth.login("alice", "wrong password!!")
    with pytest.raises(AuthError) as unknown:
        auth.login("nobody", PASSWORD)
    assert str(wrong.value) == str(unknown.value) == INVALID_CREDENTIALS


def test_lockout_after_5_failures(auth, clock):
    for _ in range(config.MAX_FAILED_ATTEMPTS):
        with pytest.raises(AuthError):
            auth.login("alice", "wrong password!!")
    # Même le bon mot de passe est refusé pendant le blocage, avec le même message
    with pytest.raises(AuthError) as exc:
        auth.login("alice", PASSWORD)
    assert str(exc.value) == INVALID_CREDENTIALS

    clock.advance(config.LOCKOUT_SECONDS - 1)
    with pytest.raises(AuthError):
        auth.login("alice", PASSWORD)

    clock.advance(2)  # blocage terminé
    assert auth.login("alice", PASSWORD)


def test_success_resets_failure_counter(auth, db):
    for _ in range(config.MAX_FAILED_ATTEMPTS - 1):
        with pytest.raises(AuthError):
            auth.login("alice", "wrong password!!")
    auth.login("alice", PASSWORD)
    assert db.get_user("alice").failed_attempts == 0
    # On a de nouveau droit à 4 erreurs sans blocage
    for _ in range(config.MAX_FAILED_ATTEMPTS - 1):
        with pytest.raises(AuthError):
            auth.login("alice", "wrong password!!")
    assert auth.login("alice", PASSWORD)


@pytest.mark.parametrize(
    "username", ["' OR '1'='1", "alice' --", "alice'; DROP TABLE users; --"]
)
def test_sql_injection_in_username(auth, db, username):
    with pytest.raises(AuthError) as exc:
        auth.login(username, PASSWORD)
    assert str(exc.value) == INVALID_CREDENTIALS
    with pytest.raises(AuthError):
        auth.register(username, PASSWORD, PUBKEY)
    assert db.get_user("alice") is not None  # la base est intacte


# --- Jetons ---
@pytest.mark.parametrize("token", ["", "A" * 43, "garbage", None])
def test_invalid_token(auth, token):
    with pytest.raises(AuthError) as exc:
        auth.validate_token(token)
    assert str(exc.value) == INVALID_SESSION


def test_token_expires_after_inactivity(auth, clock):
    token = auth.login("alice", PASSWORD)
    clock.advance(config.SESSION_TIMEOUT_SECONDS + 1)
    with pytest.raises(AuthError):
        auth.validate_token(token)
    with pytest.raises(AuthError):  # supprimé, pas seulement refusé
        auth.validate_token(token)


def test_activity_extends_session(auth, clock):
    token = auth.login("alice", PASSWORD)
    for _ in range(3):
        clock.advance(config.SESSION_TIMEOUT_SECONDS - 60)
        assert auth.validate_token(token) == "alice"


def test_logout_invalidates_token(auth):
    token = auth.login("alice", PASSWORD)
    assert auth.logout(token) is True
    assert auth.logout(token) is False
    with pytest.raises(AuthError):
        auth.validate_token(token)


def test_new_login_regenerates_and_revokes_old_token(auth):
    old = auth.login("alice", PASSWORD)
    new = auth.login("alice", PASSWORD)
    assert old != new
    assert auth.validate_token(new) == "alice"
    with pytest.raises(AuthError):
        auth.validate_token(old)


def test_purge_expired(auth, clock):
    auth.login("alice", PASSWORD)
    assert auth.purge_expired() == 0
    clock.advance(config.SESSION_TIMEOUT_SECONDS + 1)
    assert auth.purge_expired() == 1
