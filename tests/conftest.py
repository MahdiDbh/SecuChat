"""Fixtures partagées : certificat TLS de test, serveur sur un port libre."""

import shutil
import ssl
import subprocess  # noqa: S404 - uniquement pour générer un certificat de test

import pytest
from argon2 import PasswordHasher

from secuchat.auth import AuthService
from secuchat.db import Database
from secuchat.server import SecuChatServer, make_server_ssl_context, start_server

FAST_HASHER = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


@pytest.fixture(scope="session")
def tls_cert(tmp_path_factory):
    """Certificat auto-signé (localhost / 127.0.0.1) généré une fois pour la session."""
    return _generate_cert(tmp_path_factory.mktemp("certs"))


@pytest.fixture(scope="session")
def other_cert(tmp_path_factory):
    """Un autre certificat valide, qui n'est PAS celui du serveur."""
    return _generate_cert(tmp_path_factory.mktemp("other"))


def _generate_cert(d):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl introuvable")
    cert, key = d / "server.crt", d / "server.key"
    subprocess.run(  # noqa: S603 - arguments fixes, pas de shell
        [
            openssl, "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


@pytest.fixture
def client_ssl(tls_cert):
    """Contexte TLS client qui fait confiance uniquement au certificat de test."""
    ctx = ssl.create_default_context(cafile=str(tls_cert[0]))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


@pytest.fixture
async def running_server(tls_cert):
    """Serveur SecuChat lancé sur 127.0.0.1, port libre. Renvoie (app, port)."""
    db = Database()
    app = SecuChatServer(db, AuthService(db, hasher=FAST_HASHER))
    server = await start_server(app, "127.0.0.1", 0, make_server_ssl_context(*tls_cert))
    port = server.sockets[0].getsockname()[1]
    try:
        yield app, port
    finally:
        server.close()
        await server.wait_closed()
        db.close()
