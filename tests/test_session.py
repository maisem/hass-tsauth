"""Browser binding, replay, expiry, capacity and redirect-boundary tests."""

from types import SimpleNamespace

import pytest

from custom_components.tsidp.session import (
    SessionCapacityError,
    SessionError,
    SessionManager,
    new_browser_secret,
    validate_authorize_path,
)

RETURN = (
    "/auth/authorize?client_id=https%3A%2F%2Fhome-assistant.io%2FiOS"
    "&redirect_uri=homeassistant%3A%2F%2Fauth-callback&state=original"
)
BROWSER = "a" * 43
OTHER = "b" * 43


def auth(state="state-" + "x" * 32):
    return SimpleNamespace(state=state, nonce="nonce", code_verifier="do-not-log")


def identity():
    return SimpleNamespace(issuer="https://idp.example.ts.net", subject="stable-user-id")


def test_state_bound_and_one_use():
    store = SessionManager()
    store.add(auth(), BROWSER, RETURN)
    with pytest.raises(SessionError):
        store.consume_state(auth().state, OTHER)
    transaction = store.consume_state(auth().state, BROWSER)
    assert transaction.return_path == RETURN
    assert transaction.authorization.code_verifier == "do-not-log"
    with pytest.raises(SessionError):
        store.consume_state(auth().state, BROWSER)


def test_wrong_browser_cannot_consume_ticket():
    store = SessionManager()
    ticket = store.issue_ticket(identity(), BROWSER, "ha-owner-id")
    with pytest.raises(SessionError):
        store.consume_ticket(ticket, OTHER)
    result = store.consume_ticket(ticket, BROWSER)
    assert result.ha_user_id == "ha-owner-id"
    with pytest.raises(SessionError):
        store.consume_ticket(ticket, BROWSER)


def test_ttl_boundary():
    now = [0.0]
    store = SessionManager(clock=lambda: now[0])
    store.add(auth(), BROWSER, RETURN)
    ticket = store.issue_ticket(identity(), BROWSER, "ha-id")
    now[0] = 60
    with pytest.raises(SessionError):
        store.consume_ticket(ticket, BROWSER)
    now[0] = 300
    with pytest.raises(SessionError):
        store.consume_state(auth().state, BROWSER)


def test_expired_entries_release_capacity():
    now = [0.0]
    store = SessionManager(max_entries=1, clock=lambda: now[0])
    store.add(auth(), BROWSER, RETURN)
    with pytest.raises(SessionCapacityError):
        store.issue_ticket(identity(), BROWSER, "ha-id")
    now[0] = 300
    ticket = store.issue_ticket(identity(), BROWSER, "ha-id")
    assert store.consume_ticket(ticket, BROWSER).ha_user_id == "ha-id"


def test_capacity_is_shared_by_states_and_tickets():
    store = SessionManager(max_entries=1)
    ticket = store.issue_ticket(identity(), BROWSER, "ha-id")
    with pytest.raises(SessionCapacityError):
        store.add(auth(), BROWSER, RETURN)
    store.consume_ticket(ticket, BROWSER)
    store.add(auth(), BROWSER, RETURN)


def test_duplicate_state_does_not_overwrite_browser():
    store = SessionManager()
    store.add(auth(), BROWSER, RETURN)
    with pytest.raises(SessionError):
        store.add(auth(), OTHER, RETURN)
    assert store.consume_state(auth().state, BROWSER).return_path == RETURN


@pytest.mark.parametrize("secret", [None, "", "x", "x" * 129])
def test_invalid_browser_binding(secret):
    with pytest.raises(SessionError):
        SessionManager().add(auth(), secret, RETURN)


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.example/auth/authorize?client_id=a&redirect_uri=b",
        "//evil.example/auth/authorize?client_id=a&redirect_uri=b",
        "/evil?client_id=a&redirect_uri=b",
        "/auth/authorize?client_id=a&redirect_uri=b#fragment",
        "/auth/authorize?client_id=a&redirect_uri=b\r\nLocation:evil",
        "/auth/authorize?client_id=a&redirect_uri=b\\evil",
        "/auth/authorize?client_id=a&client_id=b&redirect_uri=c",
        "/auth/authorize?client_id=a&redirect_uri=b&state=a&state=b",
        "/auth/authorize?client_id=a",
        "/auth/authorize?client_id=&redirect_uri=b",
        "/auth/authorize?client_id=a&redirect_uri=",
        "/auth/authorize?" + "a=b&" * 50,
        "/auth/authorize?client_id=a&redirect_uri=b&x=" + "a" * 8192,
    ],
)
def test_reject_unsafe_return_paths(path):
    with pytest.raises(SessionError):
        validate_authorize_path(path)


def test_mobile_return_values_are_opaque_and_unchanged():
    assert validate_authorize_path(RETURN) == RETURN


def test_clear_discards_all_credentials():
    store = SessionManager()
    store.add(auth(), BROWSER, RETURN)
    ticket = store.issue_ticket(identity(), BROWSER, "ha-id")
    store.clear()
    with pytest.raises(SessionError):
        store.consume_state(auth().state, BROWSER)
    with pytest.raises(SessionError):
        store.consume_ticket(ticket, BROWSER)


def test_repr_omits_sensitive_values():
    store = SessionManager()
    store.add(auth(), BROWSER, RETURN)
    transaction = store.consume_state(auth().state, BROWSER)
    assert "do-not-log" not in repr(transaction)
    assert "original" not in repr(transaction)


def test_secure_cookie_secret_entropy_and_uniqueness():
    values = {new_browser_secret() for _ in range(50)}
    assert len(values) == 50
    assert all(len(v) >= 43 for v in values)


@pytest.mark.parametrize("kw", [{"max_entries": 0}, {"state_ttl": 0}, {"ticket_ttl": -1}])
def test_invalid_limits(kw):
    with pytest.raises(ValueError):
        SessionManager(**kw)
