"""Paramètres centraux de SecuChat (réseau, limites, sécurité, chemins).

Toutes les valeurs viennent de docs/SPECIFICATIONS.md (§4.2 et §6.3).
"""

import os
import re
from pathlib import Path

# --- Réseau ---
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8443
MAX_MESSAGE_SIZE = 64 * 1024  # 64 Ko : taille max d'une ligne JSON (limite de readline)
READ_TIMEOUT = 300  # secondes sans rien recevoir avant de couper la connexion
CONNECT_TIMEOUT = 10  # secondes pour établir la connexion TLS côté client
HANDSHAKE_TIMEOUT = 10  # secondes max pour la poignée de main TLS côté serveur
WRITE_TIMEOUT = 10  # secondes max pour envoyer un message à un client lent
MAX_CONNECTIONS = 200  # connexions simultanées max (anti-flood)
IP_MAX_LOGIN_FAILURES = 20  # échecs de connexion max par IP...
IP_WINDOW_SECONDS = 60  # ...sur cette fenêtre glissante

# --- Règles de gestion (§4.2) ---
# Liste blanche : lettres ASCII, chiffres, "_" et "-". Utiliser re.fullmatch / pydantic.
USERNAME_PATTERN = r"^[A-Za-z0-9_-]{3,32}$"
ROOM_PATTERN = r"^[A-Za-z0-9_-]{1,32}$"
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128

_USERNAME_RE = re.compile(USERNAME_PATTERN)
_ROOM_RE = re.compile(ROOM_PATTERN)

# --- Authentification et sessions (§6.3) ---
MAX_FAILED_ATTEMPTS = 5  # échecs consécutifs avant blocage
LOCKOUT_SECONDS = 60  # durée du blocage du compte
SESSION_TIMEOUT_SECONDS = 30 * 60  # expiration après 30 min d'inactivité
TOKEN_BYTES = 32  # 256 bits, pour secrets.token_urlsafe

# --- Chemins ---
# Dossier de données local, surchargeable par variable d'environnement (tests, VMs).
DATA_DIR = Path(os.environ.get("SECUCHAT_HOME", Path.home() / ".secuchat"))
DB_PATH = DATA_DIR / "server.db"
KEYS_DIR = DATA_DIR / "keys"  # clés privées chiffrées du client
CERT_DIR = Path("certs")
DEFAULT_CERT = CERT_DIR / "server.crt"
DEFAULT_KEY = CERT_DIR / "server.key"


def is_valid_username(value: str) -> bool:
    """Vrai si l'identifiant respecte la liste blanche (3-32 caractères)."""
    return isinstance(value, str) and _USERNAME_RE.fullmatch(value) is not None


def is_valid_room(value: str) -> bool:
    """Vrai si le nom de salon respecte la liste blanche (1-32 caractères)."""
    return isinstance(value, str) and _ROOM_RE.fullmatch(value) is not None


def is_valid_password(value: str) -> bool:
    """Vrai si le mot de passe fait entre 12 et 128 caractères."""
    return isinstance(value, str) and PASSWORD_MIN_LENGTH <= len(value) <= PASSWORD_MAX_LENGTH
