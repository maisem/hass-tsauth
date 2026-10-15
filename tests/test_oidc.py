"""Protocol tests with real library-generated signatures and no live services."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
import pytest
from authlib.oidc.core.util import create_half_hash
from joserfc import jws, jwt
from joserfc.jwk import ECKey, OctKey, RSAKey

from custom_components.tsidp.oidc import (
    MAX_RESPONSE_BYTES,
    Authorization,
    Identity,
    OIDCClient,
    OIDCConfig,
    OIDCError,
)

ISSUER = "https://idp.example.test"
CALLBACK = "https://ha.example.test/auth/external/callback"
CLIENT_ID = "home-assistant"
CODE = "private-authorization-code"
ACCESS_TOKEN = "private-access-token"


@pytest.fixture(scope="module")
def signing_keys():
    return {
        "rsa": RSAKey.generate_key(parameters={"kid": "rsa", "alg": "RS256"}),
        "ec": ECKey.generate_key(parameters={"kid": "ec", "alg": "ES256"}),
        "other": RSAKey.generate_key(parameters={"kid": "rsa", "alg": "RS256"}),
    }


class Provider:
    def __init__(self, keys, *, secret=None, issuer=ISSUER):
        self.keys = keys
        self.config = OIDCConfig(issuer, CLIENT_ID, CALLBACK, secret)
        self.metadata = {
            "issuer": issuer,
            # The actual HA network caller selects this legacy tsidp path.
            "authorization_endpoint": issuer + "/authorize/ha-backend-node?custom=preserved",
            "token_endpoint": issuer + "/token",
            "jwks_uri": issuer + "/jwks",
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
        }
        self.jwks = {"keys": [keys[name].as_dict(private=False) for name in ("rsa", "ec")]}
        self.responses = {}
        self.requests = []
        self.token = {}
        self.client = OIDCClient(self.config, transport=httpx.MockTransport(self.handle))

    def handle(self, request):
        self.requests.append(request)
        if request.url.path in self.responses:
            response = self.responses[request.url.path]
            if isinstance(response, Exception):
                raise response
            return response
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.metadata)
        if request.url.path.endswith("/jwks"):
            return httpx.Response(200, json=self.jwks)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json=self.token)
        raise AssertionError("Unexpected endpoint")

    def claims(self, authorization, **changes):
        now = int(time.time())
        return {
            "iss": self.config.issuer,
            "sub": "stable-subject",
            "aud": CLIENT_ID,
            "exp": now + 300,
            "iat": now - 1,
            "nonce": authorization.nonce,
            "name": "Display Name",
            "email": "display@example.test",
        } | changes

    def sign(self, payload, *, key="rsa", algorithm=None, headers=None):
        algorithm = algorithm or ("ES256" if key == "ec" else "RS256")
        header = {"alg": algorithm, "kid": self.keys[key].kid} | (headers or {})
        return jwt.encode(header, payload, self.keys[key], algorithms=[algorithm])

    def set_token(self, encoded):
        self.token = {
            "access_token": ACCESS_TOKEN,
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": encoded,
        }


@pytest.fixture
def provider(signing_keys):
    return Provider(signing_keys)


async def test_begin_preserves_caller_specific_discovery_url_and_pkce(provider):
    authorization = await provider.client.begin()
    parsed = urlsplit(authorization.authorization_url)
    assert parsed.path == "/authorize/ha-backend-node"
    params = parse_qs(parsed.query)
    assert params["custom"] == ["preserved"]
    assert params["client_id"] == [CLIENT_ID]
    assert params["redirect_uri"] == [CALLBACK]
    assert params["response_type"] == ["code"]
    assert params["scope"] == ["openid profile email"]
    assert params["state"] == [authorization.state]
    assert params["nonce"] == [authorization.nonce]
    assert params["code_challenge_method"] == ["S256"]
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(authorization.code_verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert params["code_challenge"] == [challenge]
    assert "code_verifier" not in params
    assert [request.url.path for request in provider.requests] == [
        "/.well-known/openid-configuration",
        "/jwks",
    ]
    other = await provider.client.begin()
    assert other.state != authorization.state
    assert other.nonce != authorization.nonce
    assert other.code_verifier != authorization.code_verifier


@pytest.mark.parametrize("key", ["rsa", "ec"])
async def test_complete_real_asymmetric_signatures_public_client(provider, key):
    authorization = await provider.client.begin()
    algorithm = "ES256" if key == "ec" else "RS256"
    claims = provider.claims(
        authorization, at_hash=create_half_hash(ACCESS_TOKEN, algorithm).decode()
    )
    provider.set_token(provider.sign(claims, key=key))
    assert await provider.client.complete(authorization, CODE) == Identity(
        ISSUER, "stable-subject", "Display Name", "display@example.test"
    )
    request = provider.requests[-1]
    assert request.method == "POST"
    assert request.url == ISSUER + "/token"
    assert "authorization" not in request.headers
    form = parse_qs(request.content.decode())
    assert form == {
        "grant_type": ["authorization_code"],
        "code": [CODE],
        "redirect_uri": [CALLBACK],
        "client_id": [CLIENT_ID],
        "code_verifier": [authorization.code_verifier],
    }


@pytest.mark.parametrize("method", ["client_secret_basic", "client_secret_post"])
async def test_confidential_client_authentication(signing_keys, method):
    provider = Provider(signing_keys, secret="private-client-secret")
    provider.metadata["token_endpoint_auth_methods_supported"] = [method]
    authorization = await provider.client.begin()
    provider.set_token(provider.sign(provider.claims(authorization)))
    await provider.client.complete(authorization, CODE)
    request = provider.requests[-1]
    form = parse_qs(request.content.decode())
    if method == "client_secret_basic":
        encoded = base64.b64encode(b"home-assistant:private-client-secret").decode()
        assert request.headers["authorization"] == "Basic " + encoded
        assert "client_secret" not in form
    else:
        assert "authorization" not in request.headers
        assert form["client_secret"] == ["private-client-secret"]


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("iss", "https://other.example.test"),
        ("iss", ISSUER + "/"),
        ("iss", None),
        ("aud", "other-client"),
        ("aud", []),
        ("aud", ["other-client"]),
        ("aud", [CLIENT_ID, 1]),
        ("aud", None),
        ("nonce", "wrong-nonce"),
        ("nonce", ""),
        ("nonce", None),
        ("sub", ""),
        ("sub", 42),
        ("sub", None),
        ("exp", 1),
        ("exp", "999999999999"),
        ("exp", True),
        ("exp", None),
        ("exp", float("inf")),
        ("exp", float("nan")),
        ("iat", "0"),
        ("iat", True),
        ("iat", None),
        ("iat", float("nan")),
        ("iat", 999999999999),
        ("nbf", 999999999999),
        ("nbf", False),
        ("nbf", None),
        ("azp", "other-client"),
        ("azp", ""),
        ("azp", None),
        ("name", ["malformed"]),
        ("email", {"malformed": True}),
        ("at_hash", "wrong-hash"),
        ("at_hash", ""),
        ("at_hash", None),
    ],
)
async def test_rejects_invalid_claims(provider, claim, value):
    authorization = await provider.client.begin()
    provider.set_token(provider.sign(provider.claims(authorization, **{claim: value})))
    with pytest.raises(OIDCError, match="Unable to complete"):
        await provider.client.complete(authorization, CODE)


@pytest.mark.parametrize("claim", ["iss", "aud", "exp", "iat", "nonce", "sub"])
async def test_rejects_missing_required_claims(provider, claim):
    authorization = await provider.client.begin()
    claims = provider.claims(authorization)
    del claims[claim]
    provider.set_token(provider.sign(claims))
    with pytest.raises(OIDCError):
        await provider.client.complete(authorization, CODE)


@pytest.mark.parametrize(
    ("audience", "azp", "accepted"),
    [
        ([CLIENT_ID], None, True),
        ([CLIENT_ID, "another-resource"], None, False),
        ([CLIENT_ID, "another-resource"], CLIENT_ID, True),
        (["another-resource"], CLIENT_ID, False),
    ],
)
async def test_audience_and_authorized_party(provider, audience, azp, accepted):
    authorization = await provider.client.begin()
    claims = provider.claims(authorization, aud=audience)
    if azp is not None:
        claims["azp"] = azp
    provider.set_token(provider.sign(claims))
    if accepted:
        assert (await provider.client.complete(authorization, CODE)).subject == "stable-subject"
    else:
        with pytest.raises(OIDCError):
            await provider.client.complete(authorization, CODE)


async def test_rejects_signature_from_other_key_with_same_kid(provider):
    authorization = await provider.client.begin()
    provider.set_token(provider.sign(provider.claims(authorization), key="other"))
    with pytest.raises(OIDCError):
        await provider.client.complete(authorization, CODE)


@pytest.mark.parametrize("algorithm", ["HS256", "none", "RS384", "ES384"])
async def test_rejects_unsupported_algorithms(provider, algorithm):
    authorization = await provider.client.begin()
    claims = provider.claims(authorization)
    if algorithm == "none":
        encoded = jws.serialize_compact(
            {"alg": "none"}, json.dumps(claims), None, algorithms=["none"]
        )
    else:
        key = {
            "HS256": OctKey.generate_key(256),
            "RS384": RSAKey.import_key(
                {
                    key: value
                    for key, value in provider.keys["rsa"].as_dict(private=True).items()
                    if key != "alg"
                }
            ),
            "ES384": ECKey.generate_key("P-384"),
        }[algorithm]
        encoded = jwt.encode({"alg": algorithm}, claims, key, algorithms=[algorithm])
    provider.set_token(encoded)
    with pytest.raises(OIDCError):
        await provider.client.complete(authorization, CODE)


@pytest.mark.parametrize("payload", ['["not", "an", "object"]', '"string"', "null", "not-json"])
async def test_rejects_signed_malformed_payload(provider, payload):
    authorization = await provider.client.begin()
    provider.set_token(
        jws.serialize_compact({"alg": "RS256", "kid": "rsa"}, payload, provider.keys["rsa"])
    )
    with pytest.raises(OIDCError):
        await provider.client.complete(authorization, CODE)


@pytest.mark.parametrize("encoded", ["not-a-jwt", "", None, 42, "a" * (33 * 1024)])
async def test_rejects_missing_or_malformed_id_token(provider, encoded):
    authorization = await provider.client.begin()
    provider.set_token(encoded)
    with pytest.raises(OIDCError):
        await provider.client.complete(authorization, CODE)


@pytest.mark.parametrize("access_token", [None, "", 42])
async def test_at_hash_requires_access_token(provider, access_token):
    authorization = await provider.client.begin()
    provider.set_token(
        provider.sign(
            provider.claims(authorization, at_hash=create_half_hash(ACCESS_TOKEN, "RS256").decode())
        )
    )
    provider.token["access_token"] = access_token
    with pytest.raises(OIDCError):
        await provider.client.complete(authorization, CODE)


@pytest.mark.parametrize(
    "endpoint",
    ["authorization_endpoint", "token_endpoint", "jwks_uri"],
)
@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.example.test/endpoint",
        "https://idp.example.test.attacker.example.test/endpoint",
        "https://127.0.0.1/endpoint",
        "https://169.254.169.254/latest/meta-data/",
        "http://idp.example.test/endpoint",
        "https://idp.example.test:444/endpoint",
        "https://user:password@idp.example.test/endpoint",
        "https://idp.example.test/endpoint#fragment",
        "https://idp.example.test/endpoint#",
        "https://idp.example.test\\@attacker.example.test/endpoint",
        "/relative",
        "//idp.example.test/endpoint",
        "https://idp.example.test/endpoint\n",
        None,
    ],
)
async def test_discovery_rejects_remote_or_unsafe_endpoint_before_use(provider, endpoint, url):
    provider.metadata[endpoint] = url
    with pytest.raises(OIDCError):
        await provider.client.begin()
    assert len(provider.requests) == 1


@pytest.mark.parametrize("issuer", ["https://attacker.example.test", ISSUER + "/", None])
async def test_discovery_requires_exact_issuer(provider, issuer):
    provider.metadata["issuer"] = issuer
    with pytest.raises(OIDCError):
        await provider.client.begin()
    assert len(provider.requests) == 1


@pytest.mark.parametrize(
    "issuer",
    [
        "http://idp.example.test",
        "https://idp.example.test?query",
        "https://idp.example.test#fragment",
        "https://username@idp.example.test",
        "https://idp.example.test:0",
        "https://idp.example.test:99999",
        "",
    ],
)
def test_rejects_unsafe_configured_issuer(issuer):
    with pytest.raises(OIDCError):
        OIDCConfig(issuer, CLIENT_ID, CALLBACK)


@pytest.mark.parametrize("client_id", ["", " ", None])
def test_client_id_required(client_id):
    with pytest.raises(OIDCError):
        OIDCConfig(ISSUER, client_id, CALLBACK)


async def test_path_issuer_preserved_exactly(signing_keys):
    provider = Provider(signing_keys, issuer=ISSUER + "/tenant/")
    authorization = await provider.client.begin()
    provider.set_token(provider.sign(provider.claims(authorization)))
    identity = await provider.client.complete(authorization, CODE)
    assert identity.issuer == ISSUER + "/tenant/"
    assert provider.requests[0].url.path == "/tenant/.well-known/openid-configuration"


@pytest.mark.parametrize("path", ["/.well-known/openid-configuration", "/jwks", "/token"])
@pytest.mark.parametrize("status", [301, 302, 307, 308])
async def test_never_follows_http_redirects(provider, path, status):
    if path == "/token":
        authorization = await provider.client.begin()
    provider.responses[path] = httpx.Response(
        status, headers={"location": "https://attacker.example.test/steal"}
    )
    with pytest.raises(OIDCError):
        if path == "/token":
            await provider.client.complete(authorization, CODE)
        else:
            await provider.client.begin()
    assert all(request.url.host == "idp.example.test" for request in provider.requests)
    assert provider.requests[-1].url.path == path


@pytest.mark.parametrize("path", ["/.well-known/openid-configuration", "/jwks", "/token"])
async def test_response_size_is_bounded(provider, path):
    if path == "/token":
        authorization = await provider.client.begin()
    provider.responses[path] = httpx.Response(200, content=b" " * (MAX_RESPONSE_BYTES + 1))
    with pytest.raises(OIDCError):
        if path == "/token":
            await provider.client.complete(authorization, CODE)
        else:
            await provider.client.begin()


class ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.reads = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    async def aclose(self):
        self.closed = True


async def test_streaming_body_cap_stops_reading_and_closes_response(provider):
    stream = ChunkStream([b"x" * (16 * 1024)] * 100)
    provider.responses["/.well-known/openid-configuration"] = httpx.Response(200, stream=stream)
    with pytest.raises(OIDCError):
        await provider.client.begin()
    assert stream.reads == MAX_RESPONSE_BYTES // (16 * 1024) + 1
    assert stream.closed


async def test_unsolicited_compression_rejected_before_reading(provider):
    stream = ChunkStream([b"not-read"])
    provider.responses["/.well-known/openid-configuration"] = httpx.Response(
        200, headers={"Content-Encoding": "gzip"}, stream=stream
    )
    with pytest.raises(OIDCError):
        await provider.client.begin()
    assert stream.reads == 0
    assert stream.closed
    assert provider.requests[0].headers["accept-encoding"] == "identity"


async def test_declared_large_body_rejected_before_reading(provider):
    stream = ChunkStream([b"not-read"])
    provider.responses["/.well-known/openid-configuration"] = httpx.Response(
        200, headers={"Content-Length": str(MAX_RESPONSE_BYTES + 1)}, stream=stream
    )
    with pytest.raises(OIDCError):
        await provider.client.begin()
    assert stream.reads == 0
    assert stream.closed


@pytest.mark.parametrize("path", ["/.well-known/openid-configuration", "/jwks", "/token"])
async def test_network_errors_redacted(provider, path, caplog):
    authorization = await provider.client.begin()
    secret = f"{CODE} {ACCESS_TOKEN} private-client-secret"
    provider.responses[path] = httpx.ReadTimeout(secret)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(OIDCError) as error:
        if path == "/token":
            await provider.client.complete(authorization, CODE)
        else:
            await provider.client.begin()
    for private in (CODE, ACCESS_TOKEN, "private-client-secret"):
        assert private not in str(error.value)
        assert private not in caplog.text
    assert error.value.__suppress_context__


@pytest.mark.parametrize("status", [200, 400, 401, 500])
async def test_token_errors_redacted(provider, status, caplog):
    authorization = await provider.client.begin()
    caplog.set_level(logging.DEBUG)
    secret = f"{CODE} {ACCESS_TOKEN} private-client-secret"
    provider.responses["/token"] = httpx.Response(
        status, json={"error": "invalid_grant", "error_description": secret}
    )
    with pytest.raises(OIDCError) as error:
        await provider.client.complete(authorization, CODE)
    for private in (CODE, ACCESS_TOKEN, "private-client-secret"):
        assert private not in str(error.value)
        assert private not in caplog.text
    assert error.value.__suppress_context__


async def test_success_does_not_log_codes_tokens_nonce_verifier(provider, caplog):
    caplog.set_level(logging.DEBUG)
    authorization = await provider.client.begin()
    encoded = provider.sign(provider.claims(authorization))
    provider.set_token(encoded)
    await provider.client.complete(authorization, CODE)
    for private in (
        CODE,
        ACCESS_TOKEN,
        encoded,
        authorization.nonce,
        authorization.code_verifier,
    ):
        assert private not in caplog.text
        assert private not in repr(authorization)


@pytest.mark.parametrize("field", ["state", "nonce", "code_verifier"])
async def test_empty_pending_authorization_rejected(provider, field):
    authorization = replace(await provider.client.begin(), **{field: ""})
    count = len(provider.requests)
    with pytest.raises(OIDCError):
        await provider.client.complete(authorization, CODE)
    assert len(provider.requests) == count


async def test_nonce_bound_to_original_authorization(provider):
    first = await provider.client.begin()
    second = await provider.client.begin()
    provider.set_token(provider.sign(provider.claims(first)))
    with pytest.raises(OIDCError):
        await provider.client.complete(second, CODE)


async def test_complete_with_new_client_fetches_discovery_from_its_own_network(provider):
    authorization = await provider.client.begin()
    provider.set_token(provider.sign(provider.claims(authorization)))
    client = OIDCClient(provider.config, transport=httpx.MockTransport(provider.handle))
    identity = await client.complete(authorization, CODE)
    assert identity.subject == "stable-subject"
    assert [request.url.path for request in provider.requests] == [
        "/.well-known/openid-configuration",
        "/jwks",
        "/.well-known/openid-configuration",
        "/jwks",
        "/token",
    ]


@pytest.mark.parametrize("algorithms", [["HS256"], ["none"], [], "RS256", None, [42]])
async def test_discovery_rejects_bad_algorithm_metadata(provider, algorithms):
    provider.metadata["id_token_signing_alg_values_supported"] = algorithms
    with pytest.raises(OIDCError):
        await provider.client.begin()


@pytest.mark.parametrize("jwks", [None, {}, {"keys": []}, {"keys": [42]}, {"keys": [{}] * 33}])
async def test_invalid_jwks_rejected(provider, jwks):
    provider.jwks = jwks
    with pytest.raises(OIDCError):
        await provider.client.begin()


async def test_header_jku_does_not_trigger_remote_key_fetch(provider):
    authorization = await provider.client.begin()
    provider.set_token(
        provider.sign(
            provider.claims(authorization),
            headers={
                "jku": "https://attacker.example.test/keys",
            },
        )
    )
    # A remote key reference can never substitute for the discovered signing key.
    try:
        await provider.client.complete(authorization, CODE)
    except OIDCError:
        pass
    assert len(provider.requests) == 3
    assert all(request.url.host == "idp.example.test" for request in provider.requests)


@pytest.mark.parametrize("parameter", ["state", "redirect_uri", "code_challenge", "client_id"])
async def test_authorization_endpoint_cannot_preseed_security_parameters(provider, parameter):
    provider.metadata["authorization_endpoint"] += "&" + parameter + "=attacker"
    with pytest.raises(OIDCError):
        await provider.client.begin()


def test_sensitive_dataclass_representations():
    config = OIDCConfig(ISSUER, CLIENT_ID, CALLBACK, "private-client-secret")
    authorization = Authorization(
        "private-state", "private-nonce", "private-verifier", "private-url"
    )
    assert "private" not in repr(config)
    assert "private" not in repr(authorization)


def test_http_client_disables_environment_and_redirects(provider, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.example.test:8000")
    client = provider.client._client()
    assert client.trust_env is False
    assert client.follow_redirects is False
    assert client.timeout.connect <= 10
    assert client.timeout.read <= 10


async def test_overall_network_operation_deadline(provider, monkeypatch):
    async def slow_handler(request):
        import asyncio

        await asyncio.Event().wait()

    from custom_components.tsidp import oidc

    monkeypatch.setattr(oidc, "OPERATION_TIMEOUT", 0.01)
    provider.client._transport = httpx.MockTransport(slow_handler)
    with pytest.raises(OIDCError, match="Unable to start"):
        await provider.client.begin()


async def test_embedded_jwk_cannot_override_discovered_keys(provider):
    authorization = await provider.client.begin()
    foreign_key = provider.keys["other"]
    provider.set_token(
        provider.sign(
            provider.claims(authorization),
            key="other",
            headers={
                "jwk": foreign_key.as_dict(private=False),
                "jku": "https://attacker.example.test/jwks",
                "x5u": "https://attacker.example.test/cert",
            },
        )
    )
    with pytest.raises(OIDCError):
        await provider.client.complete(authorization, CODE)
    assert len(provider.requests) == 3
