"""Small, explicit configuration surface; identities are never guessed by name."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

DOMAIN = "tsidp"
DEFAULT_CLIENT_ID = "home-assistant-tsidp"


def https_origin(value: Any, label: str) -> str:
    """Require a canonical HTTPS origin, with no user-controlled paths or credentials."""
    if (
        not isinstance(value, str)
        or any(ord(c) < 33 or ord(c) == 127 for c in value)
        or "?" in value
        or "#" in value
    ):
        raise ValueError(f"{label} must be an HTTPS origin")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as err:
        raise ValueError(f"{label} has an invalid port") from err
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or "%" in parsed.netloc
        or parsed.netloc.endswith(":")
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError(f"{label} must be an HTTPS origin without credentials, query or path")
    return value


def canonical_origin(value: str) -> str:
    """Match browser Origin serialization, without changing the exact issuer identifier."""
    parsed = urlsplit(value)
    hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in hostname:
        hostname = "[" + hostname + "]"
    port = f":{parsed.port}" if parsed.port not in (None, 443) else ""
    return "https://" + hostname + port


@dataclass(frozen=True)
class Settings:
    """Configuration for a single trusted issuer and the existing HA accounts it may use."""

    issuer: str
    base_url: str
    client_id: str
    users: Mapping[str, str] = field(repr=False)
    client_secret: str | None = field(default=None, repr=False)

    @property
    def callback_url(self) -> str:
        return self.base_url + "/auth/tsidp/callback"

    @property
    def bindings(self) -> dict[tuple[str, str], str]:
        return {(self.issuer, subject): user_id for subject, user_id in self.users.items()}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> Settings:
        """Validate before touching any auth providers, routes or login state."""
        if not isinstance(data, Mapping):
            raise ValueError("tsidp configuration must be a mapping")
        extra = set(data) - {"issuer", "base_url", "client_id", "client_secret", "users"}
        if extra:
            raise ValueError("Unknown tsidp configuration option")
        issuer = https_origin(data.get("issuer"), "issuer")
        base_url = canonical_origin(https_origin(data.get("base_url"), "base_url"))
        client_id = data.get("client_id", DEFAULT_CLIENT_ID)
        if (
            not isinstance(client_id, str)
            or not 1 <= len(client_id) <= 256
            or any(ord(c) < 33 or ord(c) > 126 for c in client_id)
        ):
            raise ValueError("client_id must be a nonempty printable ASCII identifier")
        client_secret = data.get("client_secret")
        if client_secret is not None and (
            not isinstance(client_secret, str) or not 1 <= len(client_secret) <= 4096
        ):
            raise ValueError("client_secret must be a nonempty secret string, or omitted")
        users = data.get("users")
        if not isinstance(users, Mapping) or not 1 <= len(users) <= 256:
            raise ValueError("users must explicitly map OIDC subjects to existing HA user IDs")
        for subject, user_id in users.items():
            if (
                not isinstance(subject, str)
                or not 1 <= len(subject) <= 512
                or any(ord(c) < 32 for c in subject)
                or not isinstance(user_id, str)
                or re.fullmatch(r"[0-9a-f]{32}", user_id) is None
            ):
                raise ValueError("users must map quoted subjects to 32-character HA user IDs")
        if len(set(users.values())) != len(users):
            raise ValueError("Only one Tailscale identity may be bound to each HA user")
        return cls(issuer, base_url, client_id, dict(users), client_secret)


def validate_mapping(data: Mapping[str, Any]) -> dict[str, Any]:
    """Validation hook used by HA's YAML check; keep its mapping representation."""
    Settings.from_mapping(data)
    return dict(data)
