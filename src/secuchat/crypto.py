"""Chiffrement de bout en bout avec PyNaCl (spec §5) : aucune primitive maison.

- Paires de clés X25519 ;
- messages : nacl.public.Box (X25519 + XSalsa20-Poly1305), nonce aléatoire par message ;
- clé privée locale chiffrée par mot de passe (Argon2id + SecretBox), fichier en 600.
"""

import base64
import binascii
import json
import os
import stat
import tempfile
from pathlib import Path

import nacl.exceptions
import nacl.utils
from nacl.public import Box, PrivateKey, PublicKey
from nacl.pwhash import argon2id
from nacl.secret import SecretBox

from secuchat import config

KEY_FILE_VERSION = 1
# Bornes acceptées pour les paramètres KDF lus dans un fichier (évite un fichier piégé
# qui demanderait des Go de mémoire).
_OPS_RANGE = (argon2id.OPSLIMIT_MIN, argon2id.OPSLIMIT_SENSITIVE)
_MEM_RANGE = (argon2id.MEMLIMIT_MIN, argon2id.MEMLIMIT_SENSITIVE)


class CryptoError(Exception):
    """Échec de chiffrement/déchiffrement ou fichier de clé invalide."""


# --- Clés ---
def generate_keypair() -> PrivateKey:
    """Nouvelle clé privée X25519 (la clé publique est priv.public_key)."""
    return PrivateKey.generate()


def public_key_b64(private_key: PrivateKey) -> str:
    """Clé publique au format envoyé au serveur (base64, 44 caractères)."""
    return base64.b64encode(bytes(private_key.public_key)).decode("ascii")


def load_public_key(value: str | PublicKey) -> PublicKey:
    """Convertit une clé publique base64 en PublicKey (lève CryptoError si invalide)."""
    if isinstance(value, PublicKey):
        return value
    try:
        return PublicKey(base64.b64decode(value, validate=True))
    except (binascii.Error, ValueError, TypeError, nacl.exceptions.CryptoError):
        raise CryptoError("invalid public key") from None


# --- Messages ---
def encrypt_for(recipient_pub: str | PublicKey, sender_priv: PrivateKey, plaintext: str) -> str:
    """Chiffre et authentifie plaintext pour un destinataire. Renvoie du base64."""
    box = Box(sender_priv, load_public_key(recipient_pub))
    encrypted = box.encrypt(plaintext.encode("utf-8"))  # nonce aléatoire de 24 octets inclus
    return base64.b64encode(bytes(encrypted)).decode("ascii")


def decrypt_from(sender_pub: str | PublicKey, recipient_priv: PrivateKey, payload: str) -> str:
    """Déchiffre un payload base64. Lève CryptoError si altéré ou mauvaise clé."""
    box = Box(recipient_priv, load_public_key(sender_pub))
    try:
        data = base64.b64decode(payload, validate=True)
        return box.decrypt(data).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError, nacl.exceptions.CryptoError):
        raise CryptoError("decryption failed") from None


# --- Stockage de la clé privée ---
def key_path_for(username: str, keys_dir: Path | None = None) -> Path:
    """Chemin du fichier de clé d'un utilisateur (identifiant validé : pas de ../)."""
    if not config.is_valid_username(username):
        raise CryptoError("invalid username")
    return Path(keys_dir or config.KEYS_DIR) / f"{username}.key"


def save_private_key(
    private_key: PrivateKey,
    password: str,
    path: Path,
    opslimit: int = argon2id.OPSLIMIT_MODERATE,
    memlimit: int = argon2id.MEMLIMIT_MODERATE,
) -> None:
    """Chiffre la clé privée avec une clé dérivée du mot de passe et l'écrit en 600."""
    salt = nacl.utils.random(argon2id.SALTBYTES)
    key = argon2id.kdf(
        SecretBox.KEY_SIZE, password.encode("utf-8"), salt, opslimit=opslimit, memlimit=memlimit
    )
    ciphertext = SecretBox(key).encrypt(bytes(private_key))
    content = json.dumps(
        {
            "version": KEY_FILE_VERSION,
            "kdf": "argon2id",
            "opslimit": opslimit,
            "memlimit": memlimit,
            "salt": base64.b64encode(salt).decode("ascii"),
            "data": base64.b64encode(bytes(ciphertext)).decode("ascii"),
        }
    ).encode("utf-8")

    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkstemp crée le fichier en 600 de façon sûre ; os.replace rend l'écriture atomique
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".key-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def load_private_key(password: str, path: Path) -> PrivateKey:
    """Lit et déchiffre la clé privée. Lève CryptoError si mot de passe faux ou fichier invalide."""
    path = Path(path)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        raw = path.read_bytes()
    except OSError:
        raise CryptoError("cannot read key file") from None
    if mode & 0o077:  # comme ssh : on refuse une clé lisible par d'autres
        raise CryptoError("key file permissions too open (expected 600)")

    try:
        doc = json.loads(raw)
        if doc.get("version") != KEY_FILE_VERSION or doc.get("kdf") != "argon2id":
            raise CryptoError("unsupported key file")
        opslimit, memlimit = doc["opslimit"], doc["memlimit"]
        if not (
            isinstance(opslimit, int) and isinstance(memlimit, int)
            and _OPS_RANGE[0] <= opslimit <= _OPS_RANGE[1]
            and _MEM_RANGE[0] <= memlimit <= _MEM_RANGE[1]
        ):
            raise CryptoError("invalid KDF parameters")
        salt = base64.b64decode(doc["salt"], validate=True)
        data = base64.b64decode(doc["data"], validate=True)
        key = argon2id.kdf(
            SecretBox.KEY_SIZE, password.encode("utf-8"), salt,
            opslimit=opslimit, memlimit=memlimit,
        )
        return PrivateKey(SecretBox(key).decrypt(data))
    except CryptoError:
        raise
    except (
        ValueError, KeyError, TypeError, AttributeError, binascii.Error,
        nacl.exceptions.CryptoError,
    ):
        # Mot de passe faux et fichier altéré donnent la même erreur
        raise CryptoError("cannot decrypt private key") from None
