"""Format des messages SecuChat : lignes JSON validées par pydantic (spec §4.3).

Deux familles de messages :
- ClientMessage : envoyés par le client, validés par le serveur (decode_client) ;
- ServerMessage : envoyés par le serveur, validés par le client (decode_server).
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter, ValidationError

from secuchat import config

# --- Types de base (listes blanches) ---
Username = Annotated[str, StringConstraints(pattern=config.USERNAME_PATTERN)]
RoomName = Annotated[str, StringConstraints(pattern=config.ROOM_PATTERN)]
Password = Annotated[
    str,
    StringConstraints(
        min_length=config.PASSWORD_MIN_LENGTH, max_length=config.PASSWORD_MAX_LENGTH
    ),
]
# Jeton secrets.token_urlsafe(32) : 43 caractères base64url
Token = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{43}$")]
# Clé publique X25519 (32 octets) en base64 standard : 43 caractères + "="
PubKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9+/]{43}=$")]
# Contenu chiffré en base64 (la taille totale de la ligne est aussi limitée)
Payload = Annotated[
    str,
    StringConstraints(
        min_length=1, max_length=config.MAX_MESSAGE_SIZE, pattern=r"^[A-Za-z0-9+/]+={0,2}$"
    ),
]
Timestamp = Annotated[int, Field(gt=0)]

MAX_RECIPIENTS = 256  # nombre max de destinataires dans un room_msg / get_pubkeys
ERROR_MAX_LENGTH = 200


class ProtocolError(Exception):
    """Message invalide (JSON cassé, schéma non respecté, trop long)."""


class _Base(BaseModel):
    # strict : pas de conversion implicite ("5" -> 5) ; forbid : champ inconnu = rejet
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


# --- Client -> serveur ---
class RegisterRequest(_Base):
    type: Literal["register"]
    username: Username
    password: Password
    pubkey: PubKey


class LoginRequest(_Base):
    type: Literal["login"]
    username: Username
    password: Password


class LogoutRequest(_Base):
    type: Literal["logout"]
    token: Token


class JoinRequest(_Base):
    type: Literal["join"]
    token: Token
    room: RoomName


class LeaveRequest(_Base):
    type: Literal["leave"]
    token: Token
    room: RoomName


class RoomMsgRequest(_Base):
    """Message de salon : un contenu chiffré par destinataire."""

    type: Literal["room_msg"]
    token: Token
    room: RoomName
    payloads: Annotated[dict[Username, Payload], Field(min_length=1, max_length=MAX_RECIPIENTS)]
    nonce_ts: Timestamp


class DmRequest(_Base):
    type: Literal["dm"]
    token: Token
    to: Username
    payload: Payload
    nonce_ts: Timestamp


class UsersRequest(_Base):
    type: Literal["users"]
    token: Token
    room: RoomName


class GetPubkeysRequest(_Base):
    type: Literal["get_pubkeys"]
    token: Token
    usernames: Annotated[list[Username], Field(min_length=1, max_length=MAX_RECIPIENTS)]


ClientMessage = Annotated[
    RegisterRequest
    | LoginRequest
    | LogoutRequest
    | JoinRequest
    | LeaveRequest
    | RoomMsgRequest
    | DmRequest
    | UsersRequest
    | GetPubkeysRequest,
    Field(discriminator="type"),
]


# --- Serveur -> client ---
class OkResponse(_Base):
    """Réponse positive à une requête ; seuls les champs utiles sont remplis."""

    type: Literal["ok"]
    request: Literal[
        "register", "login", "logout", "join", "leave", "room_msg", "dm", "users", "get_pubkeys"
    ]
    token: Token | None = None
    users: list[Username] | None = None
    pubkeys: dict[Username, PubKey] | None = None


class ErrorMessage(_Base):
    """Erreur générique : jamais de détail technique."""

    type: Literal["error"]
    message: Annotated[str, StringConstraints(min_length=1, max_length=ERROR_MAX_LENGTH)]


class EventMessage(_Base):
    """Notification : quelqu'un rejoint ou quitte un salon (F7)."""

    type: Literal["event"]
    event: Literal["join", "leave"]
    room: RoomName
    username: Username


class RoomMsgDelivery(_Base):
    """Message de salon relayé à un destinataire (seulement son contenu chiffré)."""

    type: Literal["room_msg"]
    room: RoomName
    sender: Username
    payload: Payload
    nonce_ts: Timestamp


class DmDelivery(_Base):
    type: Literal["dm"]
    sender: Username
    payload: Payload
    nonce_ts: Timestamp


ServerMessage = Annotated[
    OkResponse | ErrorMessage | EventMessage | RoomMsgDelivery | DmDelivery,
    Field(discriminator="type"),
]

_client_adapter: TypeAdapter = TypeAdapter(ClientMessage)
_server_adapter: TypeAdapter = TypeAdapter(ServerMessage)


def encode(message: _Base) -> bytes:
    """Sérialise un message en une ligne JSON terminée par '\\n'."""
    data = message.model_dump_json(exclude_none=True).encode("utf-8") + b"\n"
    if len(data) > config.MAX_MESSAGE_SIZE:
        raise ProtocolError("message too large")
    return data


def _decode(adapter: TypeAdapter, line: bytes | str):
    if isinstance(line, str):
        line = line.encode("utf-8")
    if len(line) > config.MAX_MESSAGE_SIZE:
        raise ProtocolError("message too large")
    try:
        return adapter.validate_json(line.rstrip(b"\r\n"))
    except ValidationError:
        # "from None" : l'erreur pydantic contient les valeurs reçues (ex. mot de passe),
        # on ne la propage pas pour qu'elle ne finisse jamais dans les logs.
        raise ProtocolError("invalid message") from None


def decode_client(line: bytes | str):
    """Valide une ligne reçue par le serveur. Lève ProtocolError si invalide."""
    return _decode(_client_adapter, line)


def decode_server(line: bytes | str):
    """Valide une ligne reçue par le client. Lève ProtocolError si invalide."""
    return _decode(_server_adapter, line)
