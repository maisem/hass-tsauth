"""Tailscale Serve identity, trusted only across an explicitly configured transport."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any

from .oidc import Identity

SERVE_ISSUER = "tailscale-serve"
LOGIN_HEADER = "Tailscale-User-Login"


def proxy_address(value: str) -> IPv4Address | IPv6Address:
    """Accept exact IP literals only, never networks, hostnames or scoped addresses."""
    if not isinstance(value, str) or "%" in value:
        raise ValueError("trusted_proxies must contain exact IP addresses")
    address = ip_address(value)
    # Dual-stack listeners can report an IPv4 peer as an IPv4-mapped IPv6 address.
    if isinstance(address, IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def valid_login(value: Any) -> bool:
    """Use the exact login, without email inference or lossy normalization."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 512
        and all(ord(char) >= 33 and ord(char) != 127 for char in value)
        and "," not in value
    )


class HeaderIdentity:
    """Never use request.remote: HA rewrites it from X-Forwarded-For."""

    def __init__(self, trusted_proxies: tuple[str, ...]) -> None:
        if not trusted_proxies:
            raise ValueError("Header authentication requires an explicit trusted proxy")
        self.trusted_proxies = frozenset(proxy_address(value) for value in trusted_proxies)

    def read(self, request: Any) -> Identity | None:
        transport = request.transport
        if transport is None:
            return None
        peer = transport.get_extra_info("peername")
        if not isinstance(peer, tuple) or len(peer) < 2:
            return None
        try:
            if proxy_address(peer[0]) not in self.trusted_proxies:
                return None
        except ValueError:
            return None
        values = request.headers.getall(LOGIN_HEADER, [])
        # Duplicate fields and comma-combined values are never identities.
        if len(values) != 1 or not valid_login(values[0]):
            return None
        return Identity(issuer=SERVE_ISSUER, subject=values[0], name=None, email=None)
