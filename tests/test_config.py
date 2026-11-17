"""Tests des constantes et validateurs de config.py."""

import pytest

from secuchat import config


def test_spec_values():
    assert config.DEFAULT_PORT == 8443
    assert config.MAX_MESSAGE_SIZE == 65536
    assert config.MAX_FAILED_ATTEMPTS == 5
    assert config.LOCKOUT_SECONDS == 60
    assert config.SESSION_TIMEOUT_SECONDS == 1800


@pytest.mark.parametrize("name", ["bob", "alice_42", "Jean-Paul", "a" * 32])
def test_valid_usernames(name):
    assert config.is_valid_username(name)


@pytest.mark.parametrize(
    "name",
    ["ab", "a" * 33, "bob space", "bob\n", "admin'--", "élise", "", "../etc", None],
)
def test_invalid_usernames(name):
    assert not config.is_valid_username(name)


def test_rooms():
    assert config.is_valid_room("p")
    assert config.is_valid_room("projet-devsecops")
    assert not config.is_valid_room("")
    assert not config.is_valid_room("salon#1")


def test_passwords():
    assert config.is_valid_password("x" * 12)
    assert config.is_valid_password("x" * 128)
    assert not config.is_valid_password("x" * 11)
    assert not config.is_valid_password("x" * 129)
