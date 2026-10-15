"""Bounded, expiring, one-use browser state. No tokens are stored on disk."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeVar
from urllib.parse import parse_qs, urlsplit

if TYPE_CHECKING:
    from .oidc import Authorization, Identity


class SessionError(Exception):
    """The login state is missing, expired, already used, or browser-mismatched."""


class SessionCapacityError(SessionError):
    """Too many concurrent logins; fail closed instead of growing indefinitely."""


@dataclass(frozen=True)
class Transaction:
    """An OIDC round trip and its original same-origin HA authorize request."""

    authorization: Authorization = field(repr=False)
    return_path: str = field(repr=False)


@dataclass(frozen=True)
class LoginTicket:
    """A verified identity approved for one explicitly selected HA account."""

    identity: Identity = field(repr=False)
    ha_user_id: str
    return_path: str | None = field(default=None, repr=False)


T = TypeVar("T")


@dataclass(frozen=True)
class _Entry[T]:
    binding: bytes = field(repr=False)
    expires_at: float
    value: T = field(repr=False)


def new_browser_secret() -> str:
    """Return an opaque secret suitable for a Secure/HttpOnly browser cookie."""
    return secrets.token_urlsafe(32)


def validate_authorize_path(path: str) -> str:
    """Accept only HA's local authorization page, never arbitrary redirects.

    HA remains responsible for verifying the client's client_id/redirect_uri.
    This validation only constrains our return navigation to the same HA origin.
    """
    if not isinstance(path, str) or len(path) > 8192 or any(ord(c) < 32 for c in path):
        raise SessionError("Invalid Home Assistant authorization request")
    parsed = urlsplit(path)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or parsed.path != "/auth/authorize"
        or "\\" in path
    ):
        raise SessionError("Invalid Home Assistant authorization request")
    try:
        query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=40)
    except ValueError as err:
        raise SessionError("Invalid Home Assistant authorization request") from err
    for name in ("client_id", "redirect_uri"):
        if len(query.get(name, [])) != 1 or not query[name][0]:
            raise SessionError("Invalid Home Assistant authorization request")
    if len(query.get("state", [])) > 1:
        raise SessionError("Invalid Home Assistant authorization request")
    return path


class SessionManager:
    """Synchronous state transitions are atomic on HA's event loop.

    Each callback consumes its state BEFORE token exchange. A wrong browser
    cannot consume another browser's state. Authentication tickets are a
    separate, shorter-lived, one-use step for HA's normal auth flow.
    """

    def __init__(
        self,
        *,
        max_entries: int = 256,
        state_ttl: float = 300,
        ticket_ttl: float = 60,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_entries < 1 or state_ttl <= 0 or ticket_ttl <= 0:
            raise ValueError("Session limits must be positive")
        self._max_entries = max_entries
        self._state_ttl = state_ttl
        self._ticket_ttl = ticket_ttl
        self._clock = clock
        self._states: dict[str, _Entry[Transaction]] = {}
        self._tickets: dict[str, _Entry[LoginTicket]] = {}

    @staticmethod
    def _binding(secret: str) -> bytes:
        if not isinstance(secret, str) or not 32 <= len(secret) <= 128:
            raise SessionError("Invalid login session")
        return hashlib.sha256(secret.encode()).digest()

    def prune(self) -> None:
        """Discard expired records; their contents never appear in log messages."""
        now = self._clock()
        for table in (self._states, self._tickets):
            expired = [key for key, value in table.items() if value.expires_at <= now]
            for key in expired:
                del table[key]

    def _reserve(self) -> None:
        self.prune()
        if len(self._states) + len(self._tickets) >= self._max_entries:
            raise SessionCapacityError("Too many active logins; please try again later")

    def add(self, authorization: Authorization, browser_secret: str, return_path: str) -> None:
        """Remember a new authorization state with a hashed browser binding."""
        binding = self._binding(browser_secret)
        validate_authorize_path(return_path)
        self._reserve()
        state = authorization.state
        if not state or len(state) > 256 or state in self._states:
            raise SessionError("Invalid login session")
        self._states[state] = _Entry(
            binding,
            self._clock() + self._state_ttl,
            Transaction(authorization, return_path),
        )

    def _consume(self, table: dict[str, _Entry[T]], key: str, browser_secret: str) -> T:
        binding = self._binding(browser_secret)
        self.prune()
        entry = table.get(key)
        if entry is None or not hmac.compare_digest(entry.binding, binding):
            raise SessionError("Login session expired or invalid; please sign in again")
        del table[key]
        return entry.value

    def consume_state(self, state: str, browser_secret: str) -> Transaction:
        """Atomically consume state for this browser, rejecting replay."""
        return self._consume(self._states, state, browser_secret)

    def issue_ticket(
        self,
        identity: Identity,
        browser_secret: str,
        ha_user_id: str,
        return_path: str | None = None,
    ) -> str:
        """Create a one-use HA handoff, not a reusable bearer access token."""
        binding = self._binding(browser_secret)
        if return_path is not None:
            validate_authorize_path(return_path)
        if not ha_user_id:
            raise SessionError("No Home Assistant account is linked")
        self._reserve()
        ticket = secrets.token_urlsafe(32)
        self._tickets[ticket] = _Entry(
            binding,
            self._clock() + self._ticket_ttl,
            LoginTicket(identity, ha_user_id, return_path),
        )
        return ticket

    def consume_ticket(self, ticket: str, browser_secret: str) -> LoginTicket:
        """Consume a handoff for HA's native login provider."""
        return self._consume(self._tickets, ticket, browser_secret)

    def clear(self) -> None:
        """Forget all pending logins during unload/restart."""
        self._states.clear()
        self._tickets.clear()
