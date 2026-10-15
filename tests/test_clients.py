"""An attacker-controlled IndieAuth client must not get silent authentication."""

import pytest

from custom_components.tsidp.clients import is_trusted_client

ORIGIN = "https://ha.example.test"


@pytest.mark.parametrize(
    "client_id,redirect_uri",
    [
        (ORIGIN + "/", ORIGIN + "/?auth_callback=1"),
        ("https://home-assistant.io/iOS", "homeassistant://auth-callback"),
        ("https://home-assistant.io/android", "homeassistant://auth-callback"),
    ],
)
def test_official_clients(client_id, redirect_uri):
    assert is_trusted_client(ORIGIN, client_id, redirect_uri)


@pytest.mark.parametrize(
    "client_id,redirect_uri",
    [
        ("https://attacker.test/", "https://attacker.test/callback"),
        (ORIGIN + "/", "https://attacker.test/callback"),
        ("https://home-assistant.io/iOS", "https://attacker.test/callback"),
        ("https://home-assistant.io/android", "homeassistant://evil"),
        (ORIGIN + "/", ORIGIN + "/?auth_callback=1&redirect=https://attacker.test"),
        (ORIGIN + "/", ORIGIN + "/?auth_callback=1#https://attacker.test"),
        ("https://home-assistant.io.attacker.test/iOS", "homeassistant://auth-callback"),
        ("https://home-assistant.io/iOS@attacker.test/", "homeassistant://auth-callback"),
        (ORIGIN + "/", "https://ha.example.test.attacker.test/?auth_callback=1"),
        (ORIGIN + "/", ORIGIN + "/evil?auth_callback=1"),
    ],
)
def test_reject_silent_third_party_authorization(client_id, redirect_uri):
    assert not is_trusted_client(ORIGIN, client_id, redirect_uri)
