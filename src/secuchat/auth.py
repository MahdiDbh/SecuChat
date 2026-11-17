"""Authentification : comptes (Argon2id), anti brute-force et sessions (spec §6.3)."""

import base64
import binascii
import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from secuchat import config
from secuchat.db import Database, UserExistsError

logger = logging.getLogger(__name__)

# Messages génériques renvoyés au client (aucun détail exploitable)
INVALID_CREDENTIALS = "invalid credentials"
REGISTRATION_FAILED = "registration failed"
INVALID_SESSION = "invalid session"


class AuthError(Exception):
    """Échec d'authentification ; str(exc) est un message générique montrable au client."""


@dataclass
class Session:
    username: str
    last_seen: float


class AuthService:
    """Gère inscription, connexion, déconnexion et jetons de session."""

    def __init__(
        self,
        db: Database,
        hasher: PasswordHasher | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self._db = db
        self._hasher = hasher or PasswordHasher()  # paramètres par défaut = Argon2id
        self._clock = clock
        self._sessions: dict[str, Session] = {}
        # Hash factice : on fait un vrai calcul Argon2 même si l'utilisateur n'existe pas,
        # pour que le temps de réponse ne révèle pas quels comptes existent.
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(16))

    # --- Comptes ---
    def register(self, username: str, password: str, pubkey: str) -> None:
        """Crée un compte. Lève AuthError (message générique) en cas d'échec."""
        if not (config.is_valid_username(username) and config.is_valid_password(password)):
            raise AuthError(REGISTRATION_FAILED)
        if not _is_valid_pubkey(pubkey):
            raise AuthError(REGISTRATION_FAILED)
        try:
            self._db.create_user(username, self._hasher.hash(password), pubkey)
        except UserExistsError:
            logger.info("registration refused: username already taken (%s)", username)
            raise AuthError(REGISTRATION_FAILED) from None
        logger.info("user registered: %s", username)

    def login(self, username: str, password: str) -> str:
        """Vérifie les identifiants et renvoie un nouveau jeton de session."""
        user = self._db.get_user(username) if config.is_valid_username(username) else None
        if user is None:
            self._burn_time(password)
            logger.info("login failed: unknown user")
            raise AuthError(INVALID_CREDENTIALS)

        now = self._clock()
        if user.locked_until > now:
            self._burn_time(password)
            logger.warning("login refused: account locked (%s)", username)
            raise AuthError(INVALID_CREDENTIALS)

        try:
            self._hasher.verify(user.pwd_hash, password)
        except (VerificationError, InvalidHashError):
            failures = user.failed_attempts + 1
            locked_until = 0.0
            if failures >= config.MAX_FAILED_ATTEMPTS:
                locked_until = now + config.LOCKOUT_SECONDS
                failures = 0  # nouveau cycle de 5 tentatives après le blocage
                logger.warning("account locked after too many failures (%s)", username)
            self._db.update_login_state(user.id, failures, locked_until)
            logger.info("login failed: bad password (%s)", username)
            raise AuthError(INVALID_CREDENTIALS) from None

        # Succès : remise à zéro du compteur, rehash si les paramètres ont changé
        self._db.update_login_state(user.id, 0, 0.0)
        if self._hasher.check_needs_rehash(user.pwd_hash):
            self._db.update_password_hash(user.id, self._hasher.hash(password))

        # Un seul jeton actif par utilisateur : l'ancien est invalidé
        self._drop_sessions_of(username)
        token = secrets.token_urlsafe(config.TOKEN_BYTES)
        self._sessions[token] = Session(username=username, last_seen=now)
        logger.info("login ok: %s", username)
        return token

    # --- Sessions ---
    def validate_token(self, token: str) -> str:
        """Renvoie l'utilisateur associé au jeton, ou lève AuthError.

        Chaque appel valide repousse l'expiration (30 min d'inactivité).
        """
        session = self._sessions.get(token) if isinstance(token, str) else None
        if session is None:
            raise AuthError(INVALID_SESSION)
        now = self._clock()
        if now - session.last_seen > config.SESSION_TIMEOUT_SECONDS:
            del self._sessions[token]
            logger.info("session expired: %s", session.username)
            raise AuthError(INVALID_SESSION)
        session.last_seen = now
        return session.username

    def logout(self, token: str) -> bool:
        """Invalide le jeton. Renvoie True s'il existait."""
        session = self._sessions.pop(token, None)
        if session:
            logger.info("logout: %s", session.username)
        return session is not None

    def purge_expired(self) -> int:
        """Supprime les sessions expirées ; renvoie le nombre supprimé."""
        now = self._clock()
        expired = [
            t for t, s in self._sessions.items()
            if now - s.last_seen > config.SESSION_TIMEOUT_SECONDS
        ]
        for token in expired:
            del self._sessions[token]
        return len(expired)

    # --- Interne ---
    def _drop_sessions_of(self, username: str) -> None:
        for token in [t for t, s in self._sessions.items() if s.username == username]:
            del self._sessions[token]

    def _burn_time(self, password: str) -> None:
        """Calcul Argon2 inutile pour égaliser le temps de réponse."""
        try:
            self._hasher.verify(self._dummy_hash, password)
        except (VerificationError, InvalidHashError):
            pass


def _is_valid_pubkey(pubkey: str) -> bool:
    """Clé publique X25519 : base64 valide de exactement 32 octets."""
    if not isinstance(pubkey, str):
        return False
    try:
        return len(base64.b64decode(pubkey, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False
