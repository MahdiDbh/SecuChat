"""Accès SQLite de SecuChat. Toutes les requêtes sont paramétrées (placeholders "?").

Ce module ne contient aucune règle métier : il lit et écrit, auth.py et server.py décident.
"""

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    pwd_hash        TEXT    NOT NULL,
    pubkey          TEXT    NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    REAL    NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS rooms (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT    NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS room_members (
    room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (room_id, user_id)
);
"""


class UserExistsError(Exception):
    """L'identifiant est déjà pris."""


@dataclass(frozen=True)
class User:
    id: int
    username: str
    pwd_hash: str
    pubkey: str
    failed_attempts: int
    locked_until: float


class Database:
    """Connexion SQLite et opérations sur les utilisateurs et les salons."""

    def __init__(self, path: str | Path = ":memory:"):
        if str(path) != ":memory:":
            path = Path(path)
            # Dossier privé + fichier en 600 : la base contient les hashs (OS7)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not path.exists():
                path.touch(mode=0o600)
            os.chmod(path, 0o600)
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- Utilisateurs ---
    def create_user(self, username: str, pwd_hash: str, pubkey: str) -> int:
        """Crée un utilisateur et renvoie son id. Lève UserExistsError si déjà pris."""
        try:
            with self._conn:
                cur = self._conn.execute(
                    "INSERT INTO users (username, pwd_hash, pubkey) VALUES (?, ?, ?)",
                    (username, pwd_hash, pubkey),
                )
        except sqlite3.IntegrityError:
            raise UserExistsError(username) from None
        return cur.lastrowid

    def get_user(self, username: str) -> User | None:
        row = self._conn.execute(
            "SELECT id, username, pwd_hash, pubkey, failed_attempts, locked_until "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return User(**dict(row)) if row else None

    def update_login_state(self, user_id: int, failed_attempts: int, locked_until: float) -> None:
        """Met à jour le compteur d'échecs et la date de fin de blocage."""
        with self._conn:
            self._conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (failed_attempts, locked_until, user_id),
            )

    def update_password_hash(self, user_id: int, pwd_hash: str) -> None:
        """Remplace le hash (utile quand argon2 demande un rehash)."""
        with self._conn:
            self._conn.execute(
                "UPDATE users SET pwd_hash = ? WHERE id = ?", (pwd_hash, user_id)
            )

    def get_pubkeys(self, usernames: list[str]) -> dict[str, str]:
        """Renvoie {username: pubkey} pour les utilisateurs existants."""
        result = {}
        for name in usernames:  # une requête par nom : pas de SQL construit dynamiquement
            row = self._conn.execute(
                "SELECT pubkey FROM users WHERE username = ?", (name,)
            ).fetchone()
            if row:
                result[name] = row["pubkey"]
        return result

    # --- Salons ---
    def _room_id(self, room: str) -> int | None:
        row = self._conn.execute("SELECT id FROM rooms WHERE name = ?", (room,)).fetchone()
        return row["id"] if row else None

    def add_member(self, room: str, username: str) -> bool:
        """Ajoute l'utilisateur au salon (créé s'il n'existe pas).

        Renvoie True s'il vient d'être ajouté, False s'il était déjà membre
        ou si l'utilisateur n'existe pas.
        """
        user = self.get_user(username)
        if user is None:
            return False
        with self._conn:
            self._conn.execute("INSERT OR IGNORE INTO rooms (name) VALUES (?)", (room,))
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO room_members (room_id, user_id) "
                "SELECT id, ? FROM rooms WHERE name = ?",
                (user.id, room),
            )
        return cur.rowcount == 1

    def remove_member(self, room: str, username: str) -> bool:
        """Retire l'utilisateur du salon. Renvoie True s'il était membre."""
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM room_members WHERE "
                "room_id = (SELECT id FROM rooms WHERE name = ?) AND "
                "user_id = (SELECT id FROM users WHERE username = ?)",
                (room, username),
            )
        return cur.rowcount == 1

    def is_member(self, room: str, username: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM room_members rm "
            "JOIN rooms r ON r.id = rm.room_id JOIN users u ON u.id = rm.user_id "
            "WHERE r.name = ? AND u.username = ?",
            (room, username),
        ).fetchone()
        return row is not None

    def list_members(self, room: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT u.username FROM room_members rm "
            "JOIN rooms r ON r.id = rm.room_id JOIN users u ON u.id = rm.user_id "
            "WHERE r.name = ? ORDER BY u.username",
            (room,),
        ).fetchall()
        return [row["username"] for row in rows]

    def rooms_of(self, username: str) -> list[str]:
        """Salons dont l'utilisateur est membre (pour les events à la déconnexion)."""
        rows = self._conn.execute(
            "SELECT r.name FROM room_members rm "
            "JOIN rooms r ON r.id = rm.room_id JOIN users u ON u.id = rm.user_id "
            "WHERE u.username = ? ORDER BY r.name",
            (username,),
        ).fetchall()
        return [row["name"] for row in rows]
