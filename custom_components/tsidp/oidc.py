"""Small, HA-independent OIDC authorization-code client.

The caller owns one-shot state, browser-session binding and authorization expiry.
Only call ``complete`` after checking those bindings. Provider URLs come from
discovery fetched by this process, not from a browser or a different machine:
tsidp can return a caller-specific ``/authorize/<node>`` endpoint.
"""

from __future__ import annotations

import asyncio
import math
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx2 as httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oidc.core import CodeIDToken
from joserfc import jwt
from joserfc.jwk import KeySet

ALGORITHMS = ("RS256", "ES256")
MAX_RESPONSE_BYTES = 256 * 1024
MAX_ID_TOKEN_BYTES = 32 * 1024
REQUEST_TIMEOUT = 10.0
OPERATION_TIMEOUT = 20.0
_PKCE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}\Z")
_AUTHORIZATION_PARAMETERS = {
    "client_id",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
}


class OIDCError(Exception):
    """A safe-to-display failure; provider responses and secrets are never included."""


def _url(value: str, *, https: bool = True) -> tuple[str, str, int]:
    """Validate a URL and return its origin, with the default port normalized."""
    if (
        not isinstance(value, str)
        or not value
        or any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in value)
    ):
        raise OIDCError("Invalid OIDC URL")
    try:
        parsed = urlsplit(value)
        schemes = ("https",) if https else ("https", "http")
        if (
            parsed.scheme not in schemes
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or "#" in value
            or "%" in parsed.netloc
        ):
            raise ValueError
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError
        return parsed.scheme, parsed.hostname.lower(), port
    except (ValueError, TypeError):
        raise OIDCError("Invalid OIDC URL") from None


@dataclass(frozen=True, slots=True)
class OIDCConfig:
    """A fixed, administrator-configured issuer and exact callback."""

    issuer: str
    client_id: str
    callback_url: str
    client_secret: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _url(self.issuer)
        # Issuer identifiers may have a path, but never a query or fragment.
        if "?" in self.issuer:
            raise OIDCError("Invalid OIDC issuer")
        _url(self.callback_url, https=False)
        if not isinstance(self.client_id, str) or not self.client_id.strip():
            raise OIDCError("OIDC client ID is required")
        if self.client_secret is not None and not isinstance(self.client_secret, str):
            raise OIDCError("Invalid OIDC client secret")


@dataclass(frozen=True, slots=True)
class Authorization:
    """Server-side pending authorization. Do not log or expose its verifier."""

    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_verifier: str = field(repr=False)
    authorization_url: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class Identity:
    """Only issuer/subject constitute an identity; name and email are display data."""

    issuer: str
    subject: str
    name: str | None = None
    email: str | None = None


@dataclass(frozen=True, slots=True)
class _Provider:
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    algorithms: tuple[str, ...]
    auth_method: str
    keys: KeySet


class _BoundedTransport(httpx.AsyncBaseTransport):
    """Bound responses, disallow redirects and pin all requests to the IdP."""

    def __init__(self, issuer: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._origin = _url(issuer)
        self._owned = transport is None
        self._inner = (
            transport
            if transport is not None
            else httpx.AsyncHTTPTransport(trust_env=False, retries=0)
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if _url(str(request.url)) != self._origin:
            raise OIDCError("OIDC endpoint origin mismatch")
        # These small JSON documents do not need compression. Refusing unsolicited
        # compression avoids allocating a decompression bomb before enforcing the cap.
        request.headers["Accept-Encoding"] = "identity"
        response = await self._inner.handle_async_request(request)
        try:
            # Reject before reading a potentially unbounded error or redirect body.
            if not 200 <= response.status_code < 300:
                raise OIDCError("OIDC provider request failed")
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise OIDCError("Unsupported OIDC response encoding")
            if "content-length" in response.headers and not (
                0 <= int(response.headers["content-length"]) <= MAX_RESPONSE_BYTES
            ):
                raise OIDCError("OIDC provider response is too large")
            body = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=16 * 1024):
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise OIDCError("OIDC provider response is too large")
            # Already decoded: do not apply Content-Encoding a second time.
            headers = [
                (key, value)
                for key, value in response.headers.multi_items()
                if key.lower() not in ("content-encoding", "content-length")
            ]
            return httpx.Response(
                response.status_code, headers=headers, content=bytes(body), request=request
            )
        finally:
            await response.aclose()

    async def aclose(self) -> None:
        if self._owned:
            await self._inner.aclose()


class OIDCClient:
    """An independent OIDC client. Optional injected transport is caller-owned."""

    def __init__(
        self, config: OIDCConfig, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.config = config
        self._transport = transport
        self._provider: _Provider | None = None

    def _client(self, auth_method: str = "none") -> AsyncOAuth2Client:
        return AsyncOAuth2Client(
            client_id=self.config.client_id,
            client_secret=self.config.client_secret,
            token_endpoint_auth_method=auth_method,
            redirect_uri=self.config.callback_url,
            scope="openid profile email",
            code_challenge_method="S256",
            timeout=httpx.Timeout(REQUEST_TIMEOUT),
            follow_redirects=False,
            trust_env=False,
            transport=_BoundedTransport(self.config.issuer, self._transport),
        )

    def _endpoint(self, value: Any) -> str:
        if _url(value) != _url(self.config.issuer):
            raise OIDCError("OIDC endpoint origin mismatch")
        return value

    async def _discover(self, client: AsyncOAuth2Client) -> _Provider:
        discovery_url = self.config.issuer.rstrip("/") + "/.well-known/openid-configuration"
        response = await client.request("GET", discovery_url, withhold_token=True)
        metadata = response.json()
        if not isinstance(metadata, dict) or metadata.get("issuer") != self.config.issuer:
            raise OIDCError("OIDC discovery issuer mismatch")
        authorization_endpoint = self._endpoint(metadata.get("authorization_endpoint"))
        token_endpoint = self._endpoint(metadata.get("token_endpoint"))
        jwks_uri = self._endpoint(metadata.get("jwks_uri"))
        if _AUTHORIZATION_PARAMETERS.intersection(
            key for key, _ in parse_qsl(urlsplit(authorization_endpoint).query)
        ):
            raise OIDCError("Invalid OIDC authorization endpoint")
        advertised_algorithms = metadata.get("id_token_signing_alg_values_supported", ALGORITHMS)
        if not isinstance(advertised_algorithms, (list, tuple)) or not all(
            isinstance(algorithm, str) for algorithm in advertised_algorithms
        ):
            raise OIDCError("Invalid OIDC signing algorithms")
        algorithms = tuple(
            algorithm for algorithm in ALGORITHMS if algorithm in advertised_algorithms
        )
        if not algorithms:
            raise OIDCError("No supported OIDC signing algorithm")
        auth_method = "none"
        if self.config.client_secret:
            methods = metadata.get("token_endpoint_auth_methods_supported", ["client_secret_basic"])
            if not isinstance(methods, list):
                raise OIDCError("Invalid OIDC token authentication methods")
            auth_method = next(
                (
                    method
                    for method in ("client_secret_basic", "client_secret_post")
                    if method in methods
                ),
                "",
            )
            if not auth_method:
                raise OIDCError("Unsupported OIDC token authentication method")
        response = await client.request("GET", jwks_uri, withhold_token=True)
        jwks = response.json()
        if (
            not isinstance(jwks, dict)
            or not isinstance(jwks.get("keys"), list)
            or not 1 <= len(jwks["keys"]) <= 32
            or not all(isinstance(key, dict) for key in jwks["keys"])
        ):
            raise OIDCError("Invalid OIDC signing keys")
        # Only public, asymmetric signing keys. Remote jku/x5u headers are never fetched.
        keys = [
            key
            for key in jwks["keys"]
            if key.get("kty") in ("RSA", "EC")
            and key.get("use", "sig") == "sig"
            and key.get("alg", algorithms[0]) in algorithms
            and "verify" in key.get("key_ops", ["verify"])
            and "d" not in key
        ]
        return _Provider(
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
            algorithms,
            auth_method,
            KeySet.import_key_set({"keys": keys}),
        )

    async def begin(self) -> Authorization:
        """Fetch discovery/JWKS locally and create a PKCE S256 authorization."""
        try:
            async with asyncio.timeout(OPERATION_TIMEOUT), self._client() as client:
                provider = await self._discover(client)
                state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                verifier = secrets.token_urlsafe(48)
                url, state = client.create_authorization_url(
                    provider.authorization_endpoint,
                    state=state,
                    nonce=nonce,
                    code_verifier=verifier,
                )
                self._provider = provider
                return Authorization(state, nonce, verifier, url)
        except Exception:
            raise OIDCError("Unable to start OIDC authorization") from None

    async def complete(self, authorization: Authorization, code: str) -> Identity:
        """Exchange a code after the caller consumes its session-bound state."""
        try:
            if (
                not isinstance(authorization, Authorization)
                or not isinstance(authorization.state, str)
                or not authorization.state
                or not isinstance(authorization.nonce, str)
                or not authorization.nonce
                or not isinstance(authorization.code_verifier, str)
                or not _PKCE_VERIFIER.fullmatch(authorization.code_verifier)
                or not isinstance(code, str)
                or not code
                or len(code) > 8192
            ):
                raise OIDCError("Invalid OIDC authorization")
            async with asyncio.timeout(OPERATION_TIMEOUT), self._client() as discovery_client:
                provider = self._provider or await self._discover(discovery_client)
                async with self._client(provider.auth_method) as client:
                    token = await client.fetch_token(
                        provider.token_endpoint,
                        grant_type="authorization_code",
                        code=code,
                        code_verifier=authorization.code_verifier,
                    )
                return self._identity(token, authorization.nonce, provider)
        except Exception:
            raise OIDCError("Unable to complete OIDC authorization") from None

    def _identity(self, token: dict[str, Any], nonce: str, provider: _Provider) -> Identity:
        encoded = token.get("id_token")
        if not isinstance(encoded, str) or not 0 < len(encoded) <= MAX_ID_TOKEN_BYTES:
            raise OIDCError("Invalid OIDC ID token")
        decoded = jwt.decode(encoded, provider.keys, algorithms=provider.algorithms)
        payload = decoded.claims
        if not isinstance(payload, dict):
            raise OIDCError("Invalid OIDC claims")
        for claim in ("iss", "sub", "nonce"):
            if not isinstance(payload.get(claim), str) or not payload[claim]:
                raise OIDCError("Invalid OIDC claims")
        audience = payload.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if not audiences or not all(isinstance(value, str) and value for value in audiences):
            raise OIDCError("Invalid OIDC audience")
        # JSON permits NaN in some parsers; NumericDates must be finite JSON numbers.
        for claim in ("exp", "iat", "nbf"):
            value = payload.get(claim)
            if (claim in ("exp", "iat") or claim in payload) and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise OIDCError("Invalid OIDC timestamp")
        for claim in ("name", "email", "azp"):
            if claim in payload and (not isinstance(payload[claim], str) or not payload[claim]):
                raise OIDCError("Invalid OIDC claims")
        if "at_hash" in payload and (
            not isinstance(payload["at_hash"], str)
            or not payload["at_hash"]
            or not isinstance(token.get("access_token"), str)
            or not token["access_token"]
        ):
            raise OIDCError("Invalid OIDC access token hash")
        claims = CodeIDToken(
            payload,
            decoded.header,
            options={
                "iss": {"essential": True, "value": self.config.issuer},
                "aud": {"essential": True, "value": self.config.client_id},
            },
            params={
                "nonce": nonce,
                "client_id": self.config.client_id,
                "access_token": token.get("access_token"),
            },
        )
        claims.validate(now=time.time(), leeway=0)
        return Identity(self.config.issuer, claims["sub"], claims.get("name"), claims.get("email"))
