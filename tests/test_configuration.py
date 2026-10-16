"""Validate account binding and URL configuration before affecting HA authentication."""

import pytest

from custom_components.tsidp import CONFIG_SCHEMA
from custom_components.tsidp.configuration import Settings

USER = "a" * 32
OTHER = "b" * 32


def config(**kw):
    return {
        "issuer": "https://idp.example.ts.net",
        "base_url": "https://ha.example.ts.net",
        "users": {"12345": USER},
        **kw,
    }


def test_defaults_and_subject_mapping():
    value = Settings.from_mapping(config())
    assert value.callback_url == "https://ha.example.ts.net/auth/tsidp/callback"
    assert value.client_id == "home-assistant-tsidp"
    assert value.bindings == {("https://idp.example.ts.net", "12345"): USER}
    assert value.client_secret is None


def test_does_not_expose_secret_in_repr():
    assert "super-secret" not in repr(Settings.from_mapping(config(client_secret="super-secret")))


def test_issuer_identifier_preserved_exactly():
    value = Settings.from_mapping(config(issuer="https://idp.example.ts.net/"))
    assert value.issuer == "https://idp.example.ts.net/"


@pytest.mark.parametrize("key", ["issuer", "base_url"])
@pytest.mark.parametrize(
    "value",
    [
        None,
        "http://ha.example",
        "https://user:pass@ha.example",
        "https://ha.example/path",
        "https://ha.example?x=y",
        "https://ha.example#frag",
        "https://ha.example:99999",
        "https://ha.example\r\n",
        "https://ha.example\\evil",
    ],
)
def test_bad_origins(key, value):
    with pytest.raises(ValueError):
        Settings.from_mapping(config(**{key: value}))


@pytest.mark.parametrize(
    "users",
    [{}, None, {12345: USER}, {"123": "not-a-user-id"}, {"": USER}, {"123": USER, "456": USER}],
)
def test_reject_bad_subject_bindings(users):
    with pytest.raises(ValueError):
        Settings.from_mapping(config(users=users))


def test_multiple_explicit_users():
    settings = Settings.from_mapping(config(users={"123": USER, "456": OTHER}))
    assert len(settings.bindings) == 2


@pytest.mark.parametrize("client_id", ["", "has whitespace", "x" * 257, "not-ascii-✓"])
def test_reject_bad_client_identifier(client_id):
    with pytest.raises(ValueError):
        Settings.from_mapping(config(client_id=client_id))


def test_reject_implicit_account_provisioning():
    with pytest.raises(ValueError):
        Settings.from_mapping(config(allow_any_user=True))


def test_ha_schema_keeps_other_components_and_no_mutation():
    value = {"tsidp": config(), "http": {"use_x_forwarded_for": True}}
    assert CONFIG_SCHEMA(value) == value


@pytest.mark.parametrize(
    "origin",
    [
        "https://HA.EXAMPLE.TS.NET",
        "https://ha.example.ts.net:443/",
        "https://HA.EXAMPLE.TS.NET:443",
    ],
)
def test_base_url_matches_browser_origin_serialization(origin):
    assert Settings.from_mapping(config(base_url=origin)).base_url == "https://ha.example.ts.net"


@pytest.mark.parametrize(
    "origin",
    [
        "https://ha.example?",
        "https://ha.example#",
        "https://ha.example\x7f",
        "https://ha.example%2eevil",
        "https://ha.example:",
    ],
)
def test_ambiguous_origins_rejected(origin):
    with pytest.raises(ValueError):
        Settings.from_mapping(config(base_url=origin))


def test_ipv6_origin_normalized_without_losing_brackets():
    assert Settings.from_mapping(config(base_url="https://[::1]:443/")).base_url == "https://[::1]"


def header_config(**kwargs):
    return {
        "auth_mode": "headers",
        "base_url": "https://ha.example.ts.net",
        "trusted_proxies": ["127.0.0.1", "::1"],
        "users": {"owner@example.test": USER},
        **kwargs,
    }


def test_headers_needs_no_oidc_and_uses_separate_explicit_identity_namespace():
    settings = Settings.from_mapping(header_config())
    assert settings.auth_mode == "headers"
    assert settings.bindings == {("tailscale-serve", "owner@example.test"): USER}
    assert settings.trusted_proxies == ("127.0.0.1", "::1")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"auth_mode": "anything"},
        {"trusted_proxies": []},
        {"trusted_proxies": "127.0.0.1"},
        {"trusted_proxies": ["127.0.0.0/8"]},
        {"trusted_proxies": ["localhost"]},
        {"trusted_proxies": ["*"]},
        {"issuer": "https://old.example"},
        {"client_id": "old-client"},
        {"client_secret": "old-secret"},
        {"users": {" owner@example.test": USER}},
        {"users": {"owner@example.test,attacker@example.test": USER}},
    ],
)
def test_header_config_must_be_unambiguous_and_explicit(kwargs):
    with pytest.raises(ValueError):
        Settings.from_mapping(header_config(**kwargs))


def test_headers_no_default_proxy_trust():
    data = header_config()
    del data["trusted_proxies"]
    with pytest.raises(ValueError):
        Settings.from_mapping(data)


def test_oidc_rejects_silent_ignored_proxy_options():
    with pytest.raises(ValueError):
        Settings.from_mapping(config(trusted_proxies=["127.0.0.1"]))
