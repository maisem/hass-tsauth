"""Transport-only Serve trust: forwarded addresses and client claims are not proof."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from multidict import CIMultiDict

from custom_components.tsidp.headers import (
    LOGIN_HEADER,
    SERVE_ISSUER,
    HeaderIdentity,
    proxy_address,
)

LOGIN = "owner@example.test"


def request(peer, headers=None, *, remote="127.0.0.1"):
    return SimpleNamespace(
        transport=Mock(get_extra_info=Mock(return_value=peer)),
        headers=CIMultiDict(headers if headers is not None else {LOGIN_HEADER: LOGIN}),
        remote=remote,
    )


@pytest.mark.parametrize(
    "peer",
    [
        ("127.0.0.1", 45678),
        ("::1", 45678, 0, 0),
        ("::ffff:127.0.0.1", 45678, 0, 0),
    ],
)
def test_exact_loopback_transport_not_rewritten_remote(peer):
    identity = HeaderIdentity(("127.0.0.1", "::1")).read(request(peer, remote="100.101.102.103"))
    assert identity.issuer == SERVE_ISSUER
    assert identity.subject == LOGIN
    assert identity.name is None and identity.email is None


@pytest.mark.parametrize(
    "peer",
    [
        ("192.168.1.45", 45678),
        ("100.101.102.103", 45678),
        ("fd7a:115c:a1e0::123", 45678, 0, 0),
        ("127.0.0.2", 45678),
        ("::ffff:192.168.1.45", 45678),
        ("::1%eth0", 45678),
        ("not-an-ip", 45678),
        ("127.0.0.1",),
        None,
        "/unix/socket",
    ],
)
def test_lan_tailnet_other_loopback_or_unknown_transport_cannot_spoof(peer):
    headers = {
        LOGIN_HEADER: LOGIN,
        "X-Forwarded-For": "127.0.0.1",
        "Forwarded": "for=127.0.0.1",
        "X-Real-IP": "::1",
    }
    assert HeaderIdentity(("127.0.0.1", "::1")).read(request(peer, headers)) is None


def test_missing_transport_fails_closed():
    value = request(("127.0.0.1", 1))
    value.transport = None
    assert HeaderIdentity(("127.0.0.1",)).read(value) is None


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Tailscale-User-Name": LOGIN},
        {LOGIN_HEADER: ""},
        {LOGIN_HEADER: " " + LOGIN},
        {LOGIN_HEADER: LOGIN + " "},
        {LOGIN_HEADER: LOGIN + "\t"},
        {LOGIN_HEADER: LOGIN + "\r\nother"},
        {LOGIN_HEADER: LOGIN + "\x7f"},
        {LOGIN_HEADER: LOGIN + "," + LOGIN},
        {LOGIN_HEADER: "a" * 513},
        [(LOGIN_HEADER, LOGIN), (LOGIN_HEADER, LOGIN)],
        [(LOGIN_HEADER, LOGIN), ("tailscale-user-login", "attacker@example.test")],
    ],
)
def test_absent_invalid_combined_or_duplicate_identity_is_never_accepted(headers):
    assert HeaderIdentity(("127.0.0.1",)).read(request(("127.0.0.1", 1), headers)) is None


def test_specific_verified_proxy_address_not_entire_network():
    policy = HeaderIdentity(("172.30.33.7",))
    assert policy.read(request(("172.30.33.7", 1))).subject == LOGIN
    assert policy.read(request(("172.30.33.8", 1))) is None
    assert policy.read(request(("127.0.0.1", 1))) is None


@pytest.mark.parametrize(
    "value",
    ["localhost", "127.0.0.0/8", "0.0.0.0/0", "*", "::/0", "::1%lo", "", None, 2130706433],
)
def test_only_explicit_address_literals(value):
    with pytest.raises(ValueError):
        proxy_address(value)


def test_empty_trust_list_rejected():
    with pytest.raises(ValueError):
        HeaderIdentity(())
