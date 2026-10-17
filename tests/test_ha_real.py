"""Optional real HA core smoke; run in each isolated, audited Python 3.14 venv.

This uses actual AuthManager, provider base, credential store, HTTP login-flow
views and MFA processing. It is not a browser or Companion app E2E test.
"""

# ruff: noqa: E402
from __future__ import annotations

from importlib import metadata
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlencode

import pytest

pytest.importorskip("homeassistant", reason="Optional isolated HA runtime smoke")

import voluptuous as vol
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from homeassistant.auth import InvalidAuthError, auth_manager_from_config
from homeassistant.auth.mfa_modules import MultiFactorAuthModule
from homeassistant.components import auth as ha_auth
from homeassistant.components.auth import TokenView, _create_auth_code_store
from homeassistant.components.auth import login_flow as ha_login_flow
from homeassistant.components.auth.login_flow import (
    AuthProvidersView,
    LoginFlowIndexView,
    LoginFlowResourceView,
)
from homeassistant.components.http.request_context import setup_request_context
from homeassistant.const import __version__
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.http import KEY_HASS, current_request
from yarl import URL

from custom_components.tsidp import CONFIG_SCHEMA, async_setup
from custom_components.tsidp.compatibility import SUPPORTED_HA_VERSIONS
from custom_components.tsidp.ha_adapter import (
    BRIDGE_PATH,
    BRIDGE_SCRIPT,
    BROWSER_COOKIE,
    MODE_COOKIE,
    TICKET_COOKIE,
    async_install,
)
from custom_components.tsidp.headers import LOGIN_HEADER, SERVE_ISSUER, HeaderIdentity
from custom_components.tsidp.oidc import Authorization, Identity
from custom_components.tsidp.session import SessionManager, new_browser_secret

HAS_NATIVE_PKCE = hasattr(ha_auth, "AuthCodeEntry")

ORIGIN = "https://ha.example.test"
ISSUER = "https://idp.example.test"
NATIVE_BOOTSTRAP = (
    '<script crossorigin="use-credentials">import("/frontend_latest/authorize.js");</script>'
)
NATIVE_HTML = (
    "<!doctype html><html><head><title>HA</title></head><body>native"
    + NATIVE_BOOTSTRAP
    + "</body></html>"
)


@pytest.fixture
async def runtime(tmp_path, request):
    assert __version__ in SUPPORTED_HA_VERSIONS, "Audit before changing the runtime target"
    hass = HomeAssistant(str(tmp_path))
    hass.config.skip_pip = True
    # AuthStore references the device registry when loading. No live instance,
    # external network or configuration directory is used by this fixture.
    hass.data[dr.DATA_REGISTRY] = dr.DeviceRegistry(hass)
    hass.auth = await auth_manager_from_config(hass, [{"type": "homeassistant"}], [])
    owner = await hass.auth.async_create_user("Existing Home Assistant owner")
    app = web.Application()
    app[KEY_HASS] = hass
    setup_request_context(app, current_request)
    hass.http = SimpleNamespace(
        app=app, register_view=lambda view: view.register(hass, app, app.router)
    )
    store_code, retrieve_code = _create_auth_code_store()
    hass.http.register_view(LoginFlowIndexView(hass.auth.login_flow, store_code))
    hass.http.register_view(LoginFlowResourceView(hass.auth.login_flow, store_code))
    hass.http.register_view(AuthProvidersView())
    hass.http.register_view(TokenView(retrieve_code))

    authorize_file = tmp_path / "authorize.html"
    authorize_file.write_text(NATIVE_HTML)

    async def native_authorize(_request):
        # The real HA frontend registers this exact path as a static file.
        return web.FileResponse(
            authorize_file,
            headers={"X-Native-Security": "preserved", "ETag": '"native-old"'},
        )

    app.router.add_get("/auth/authorize", native_authorize)
    originals = {
        route.get_info().get("path"): route.handler
        for route in app.router.routes()
        if route.method == "GET"
    }
    mode = getattr(request, "param", None)
    if mode in {"frozen", "setup_frozen", "headers_frozen", "headers_setup_frozen"}:
        # Mirror HomeAssistantHTTP.start: middleware/application freeze, but
        # integrations may still register new routes using the public API.
        app.router.freeze = lambda: None
        app.freeze()
        assert app.frozen and not app.router.frozen
    sessions = SessionManager()
    identity = Identity(issuer=ISSUER, subject="stable-owner-sub", name="Ignored", email=None)
    header_policy = None
    if mode and mode.startswith("headers"):
        identity = Identity(
            issuer=SERVE_ISSUER, subject="owner@example.test", name=None, email=None
        )
        header_policy = HeaderIdentity(("127.0.0.1",))
    authorization = Authorization(
        state=new_browser_secret(),
        nonce=new_browser_secret(),
        code_verifier=new_browser_secret(),
        authorization_url=ISSUER + "/authorize",
    )
    oidc = SimpleNamespace(
        begin=AsyncMock(return_value=authorization),
        complete=AsyncMock(return_value=identity),
    )
    if mode in {"headers_setup", "headers_setup_frozen"}:
        config = CONFIG_SCHEMA(
            {
                "tsidp": {
                    "auth_mode": "headers",
                    "base_url": ORIGIN,
                    "trusted_proxies": ["127.0.0.1"],
                    "users": {identity.subject: owner.id},
                }
            }
        )
        assert await async_setup(hass, config)
        handle = hass.data["tsidp"]
        sessions = handle.provider.sessions
    elif mode in {"setup", "setup_frozen"}:
        config = CONFIG_SCHEMA(
            {"tsidp": {"issuer": ISSUER, "base_url": ORIGIN, "users": {identity.subject: owner.id}}}
        )
        assert await async_setup(hass, config)
        handle = hass.data["tsidp"]
    else:
        handle = await async_install(
            hass,
            oidc=oidc,
            sessions=sessions,
            bindings={(identity.issuer, identity.subject): owner.id},
            callback_url=ORIGIN + "/auth/tsidp/callback",
            header_identity=header_policy,
        )
    client = TestClient(TestServer(app))
    await client.start_server()
    yield SimpleNamespace(
        hass=hass,
        owner=owner,
        sessions=sessions,
        identity=identity,
        oidc=oidc,
        authorization=authorization,
        provider=handle.provider,
        client=client,
        retrieve_code=retrieve_code,
        handle=handle,
        originals=originals,
    )
    await client.close()
    handle.disable()
    await hass.async_stop()


def login_request(runtime, client_id, redirect_uri, *, pkce=None):
    browser = new_browser_secret()
    path = "/auth/authorize?" + urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": "opaque+state/=",
            **(pkce or {}),
        }
    )
    ticket = runtime.sessions.issue_ticket(runtime.identity, browser, runtime.owner.id, path)
    headers = {"Origin": ORIGIN, "Cookie": f"{BROWSER_COOKIE}={browser}; {TICKET_COOKIE}={ticket}"}
    if runtime.provider.header_identity is not None:
        headers[LOGIN_HEADER] = runtime.identity.subject
    body = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "handler": ["tsidp", None],
        **(pkce or {}),
    }
    return headers, body


@pytest.mark.parametrize("runtime", [None, "headers", "headers_frozen"], indirect=True)
@pytest.mark.parametrize(
    "client_id,redirect_uri",
    [
        (ORIGIN + "/", ORIGIN + "/?auth_callback=1"),
        ("https://home-assistant.io/android", "homeassistant://auth-callback"),
        ("https://home-assistant.io/iOS", "homeassistant://auth-callback"),
    ],
)
async def test_stock_ha_code_issuance_links_existing_owner(runtime, client_id, redirect_uri):
    assert runtime.owner.is_owner
    headers, body = login_request(runtime, client_id, redirect_uri)
    response = await runtime.client.post("/auth/login_flow", json=body, headers=headers)
    result = await response.json()
    assert response.status == 200, result
    assert result["type"] == "create_entry", result
    assert "context" not in result and "data" not in result
    code = result["result"]
    assert runtime.retrieve_code("https://attacker.test", code) is None
    entry = runtime.retrieve_code(client_id, code)
    assert entry is not None
    # Native 2026.10.1 wraps credentials with optional PKCE metadata.
    credential = entry.credentials if hasattr(entry, "credentials") else entry
    assert await runtime.hass.auth.async_get_user_by_credentials(credential) is runtime.owner
    assert runtime.retrieve_code(client_id, code) is None
    assert len(await runtime.hass.auth.async_get_users()) == 1
    # Repeat sign-in must reuse, not duplicate, the existing linked credential.
    headers, body = login_request(runtime, client_id, redirect_uri)
    second = await runtime.client.post("/auth/login_flow", json=body, headers=headers)
    assert (await second.json())["type"] == "create_entry"
    assert len(await runtime.provider.async_credentials()) == 1


async def test_existing_credential_cannot_be_rebound_to_another_user(runtime):
    result = {"issuer": ISSUER, "subject": runtime.identity.subject, "ha_user_id": runtime.owner.id}
    await runtime.provider.async_get_or_create_credentials(result)
    other = await runtime.hass.auth.async_create_user("Unrelated account")
    runtime.provider.bindings[(ISSUER, runtime.identity.subject)] = other.id
    with pytest.raises(InvalidAuthError, match="different binding"):
        await runtime.provider.async_get_or_create_credentials({**result, "ha_user_id": other.id})
    assert len(other.credentials) == 0


class TestMFA(MultiFactorAuthModule):
    __test__ = False

    @property
    def input_schema(self):
        return vol.Schema({vol.Required("code"): str})

    async def async_is_user_setup(self, user_id):
        return True

    async def async_validate(self, user_id, user_input):
        return user_input.get("code") == "test-only-code"


@pytest.mark.parametrize("runtime", [None, "headers", "headers_frozen"], indirect=True)
async def test_native_ha_mfa_not_bypassed(runtime):
    runtime.hass.auth._mfa_modules["test"] = TestMFA(runtime.hass, {"type": "test"})
    client_id, redirect_uri = ORIGIN + "/", ORIGIN + "/?auth_callback=1"
    headers, body = login_request(runtime, client_id, redirect_uri)
    response = await runtime.client.post("/auth/login_flow", json=body, headers=headers)
    result = await response.json()
    assert result["type"] == "form", result
    assert result["step_id"] == "mfa"
    assert "result" not in result
    response = await runtime.client.post(
        "/auth/login_flow/" + result["flow_id"],
        json={"client_id": client_id, "code": "test-only-code"},
        headers={"Origin": ORIGIN},
    )
    completed = await response.json()
    assert completed["type"] == "create_entry", completed
    assert runtime.retrieve_code(client_id, completed["result"]) is not None


async def test_original_password_provider_still_runs_its_native_challenge(runtime):
    response = await runtime.client.post(
        "/auth/login_flow",
        headers={"Origin": ORIGIN},
        json={
            "client_id": ORIGIN + "/",
            "redirect_uri": ORIGIN + "/?auth_callback=1",
            "handler": ["homeassistant", None],
        },
    )
    result = await response.json()
    assert response.status == 200, result
    assert result["type"] == "form", result
    fields = {field["name"] for field in result["data_schema"]}
    assert {"username", "password"}.issubset(fields)


@pytest.mark.parametrize("runtime", [None, "frozen", "headers_frozen"], indirect=True)
@pytest.mark.parametrize("flag", ["tsidp_local", "tsidp_resume"])
async def test_real_file_authorize_html_loads_public_no_store_bridge(runtime, flag):
    query = (
        "client_id=https%3A%2F%2Fhome-assistant.io%2Fandroid&"
        "redirect_uri=homeassistant%3A%2F%2Fauth-callback&state=a%2Bb%2Fc%3D"
    )
    response = await runtime.client.get(f"/auth/authorize?{query}&{flag}=1")
    assert response.status == 200
    assert response.content_type == "text/html"
    html = await response.text()
    assert html == NATIVE_HTML.replace("<head>", "<head>" + BRIDGE_SCRIPT)
    # Parser blocking, not defer/async/module, must precede the pinned inline import.
    assert BRIDGE_SCRIPT == f'<script src="{BRIDGE_PATH}"></script>'
    assert html.index(BRIDGE_SCRIPT) < html.index(NATIVE_BOOTSTRAP)
    assert response.headers["X-Native-Security"] == "preserved"
    assert response.headers["Cache-Control"] == "no-store"
    assert "ETag" not in response.headers
    assert "Last-Modified" not in response.headers
    response = await runtime.client.get(BRIDGE_PATH)
    assert response.status == 200
    assert response.content_type == "application/javascript"
    assert response.headers["Cache-Control"] == "no-store"
    assert "pick-auth-provider" in await response.text()


@pytest.mark.parametrize("kind", ["missing", "expired", "replay"])
async def test_native_tsidp_ticket_retry_has_specific_restart_abort(runtime, kind):
    headers, body = login_request(runtime, ORIGIN + "/", ORIGIN + "/?auth_callback=1")
    if kind == "missing":
        headers = {"Origin": ORIGIN}
    elif kind == "expired":
        runtime.sessions._clock = lambda: float("inf")
    else:
        response = await runtime.client.post("/auth/login_flow", json=body, headers=headers)
        assert (await response.json())["type"] == "create_entry"
    response = await runtime.client.post("/auth/login_flow", json=body, headers=headers)
    result = await response.json()
    assert response.status == 200, result
    assert result["type"] == "abort", result
    assert result["handler"] == ["tsidp", None]
    assert result["reason"] == "restart_sso"
    assert "result" not in result


async def test_native_tsidp_wrong_origin_still_invalid_auth(runtime):
    headers, body = login_request(runtime, ORIGIN + "/", ORIGIN + "/?auth_callback=1")
    headers["Origin"] = "https://attacker.test"
    response = await runtime.client.post("/auth/login_flow", json=body, headers=headers)
    result = await response.json()
    assert result["type"] == "abort", result
    assert result["reason"] == "invalid_auth"
    assert "result" not in result


@pytest.mark.parametrize("runtime", ["frozen"], indirect=True)
async def test_frozen_ha_app_wraps_only_existing_routes_and_restores(runtime):
    """Exercise normal HA late setup, with its deliberately still-open router."""
    app = runtime.hass.http.app
    assert app.frozen and app.middlewares.frozen and not app.router.frozen
    assert len(runtime.handle.route_handlers) == 2
    query = urlencode(
        {
            "client_id": ORIGIN + "/",
            "redirect_uri": ORIGIN + "/?auth_callback=1",
            "state": "opaque+state/=",
        }
    )
    response = await runtime.client.get(
        URL("/auth/authorize?" + query, encoded=True), allow_redirects=False
    )
    assert response.status == 302
    assert response.headers["Location"].startswith("/auth/tsidp/start?")
    response = await runtime.client.get("/auth/authorize?" + query + "&tsidp_local=1")
    assert response.status == 200
    assert await response.text() == NATIVE_HTML.replace("<head>", "<head>" + BRIDGE_SCRIPT)
    assert response.cookies[MODE_COOKIE].value == "local"
    response = await runtime.client.get(
        "/auth/providers", headers={"Cookie": f"{MODE_COOKIE}=local"}
    )
    assert [p["type"] for p in (await response.json())["providers"]] == ["homeassistant"]
    response = await runtime.client.get(
        "/auth/providers", headers={"Cookie": f"{MODE_COOKIE}=oidc"}
    )
    assert (await response.json())["providers"][0]["type"] == "tsidp"
    # The unwrapped native login-flow route still issues the native core code.
    headers, body = login_request(runtime, ORIGIN + "/", ORIGIN + "/?auth_callback=1")
    response = await runtime.client.post("/auth/login_flow", json=body, headers=headers)
    assert (await response.json())["type"] == "create_entry"
    runtime.handle.disable()
    for route in app.router.routes():
        if route.method == "GET" and route.get_info().get("path") in {
            "/auth/authorize",
            "/auth/providers",
        }:
            assert route.handler is runtime.originals[route.get_info()["path"]]
    response = await runtime.client.get("/auth/authorize?" + query)
    assert response.status == 200
    assert await response.text() == NATIVE_HTML


@pytest.mark.parametrize("runtime", ["unfrozen", "frozen", "headers_frozen"], indirect=True)
@pytest.mark.parametrize(
    "mode,expected,remember",
    [
        ("oidc", ["tsidp", "homeassistant"], True),
        ("local", ["homeassistant"], False),
        (None, ["homeassistant", "tsidp"], False),
    ],
)
async def test_real_nonlocal_remember_preference_only_changes_for_oidc(
    runtime, monkeypatch, mode, expected, remember
):
    # Model the native endpoint's non-local result without trusting proxy
    # headers or changing any live Home Assistant configuration.
    monkeypatch.setattr(ha_login_flow, "is_local", lambda _: False)
    headers = {} if mode is None else {"Cookie": f"{MODE_COOKIE}={mode}"}
    response = await runtime.client.get("/auth/providers", headers=headers)
    result = await response.json()
    assert response.status == 200
    assert [p["type"] for p in result["providers"]] == expected
    assert result["preselect_remember_me"] is remember


@pytest.mark.parametrize("runtime", ["frozen"], indirect=True)
async def test_frozen_ha_install_failure_restores_routes_and_provider(runtime):
    runtime.handle.disable()

    def fail_register(_view):
        raise RuntimeError("simulated late registration failure")

    runtime.hass.http.register_view = fail_register
    with pytest.raises(RuntimeError, match="simulated late registration"):
        await async_install(
            runtime.hass,
            oidc=object(),
            sessions=runtime.sessions,
            bindings={(ISSUER, runtime.identity.subject): runtime.owner.id},
            callback_url=ORIGIN + "/auth/tsidp/callback",
        )
    assert runtime.hass.auth.get_auth_provider("tsidp", None) is None
    for route in runtime.hass.http.app.router.routes():
        if route.method == "GET" and route.get_info().get("path") in {
            "/auth/authorize",
            "/auth/providers",
        }:
            assert route.handler is runtime.originals[route.get_info()["path"]]


@pytest.mark.parametrize("runtime", ["setup", "setup_frozen"], indirect=True)
async def test_actual_yaml_setup_passes_guard_and_keeps_existing_owner(runtime):
    """Run actual integration setup/imports, not just the adapter entry point."""
    installed = runtime.hass.data["tsidp"]
    assert runtime.hass.auth.get_auth_provider("tsidp", None) is installed.provider
    assert installed.provider.bindings == {(ISSUER, runtime.identity.subject): runtime.owner.id}
    assert len(await runtime.hass.auth.async_get_users()) == 1


# RFC 7636 Appendix B vector, verified by HA's native TokenView, not our crypto.
PKCE = {
    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    "code_challenge_method": "S256",
}
PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


@pytest.mark.skipif(not HAS_NATIVE_PKCE, reason="Native Core has no PKCE support")
@pytest.mark.parametrize("runtime", [None, "frozen", "headers", "headers_frozen"], indirect=True)
@pytest.mark.parametrize("verifier", [None, "x" * 43, PKCE_VERIFIER])
async def test_native_pkce_code_exchange_preserves_proof_and_existing_owner(runtime, verifier):
    client_id, redirect_uri = ORIGIN + "/", ORIGIN + "/?auth_callback=1"
    headers, body = login_request(runtime, client_id, redirect_uri, pkce=PKCE)
    # Preserve both opaque state and native PKCE across our authorize redirect.
    query = urlencode(
        {"client_id": client_id, "redirect_uri": redirect_uri, "state": "a+b/=", **PKCE}
    )
    response = await runtime.client.get(
        URL("/auth/authorize?" + query, encoded=True), allow_redirects=False
    )
    assert response.status == 302
    assert response.headers["Location"] == "/auth/tsidp/start?" + query
    response = await runtime.client.post("/auth/login_flow", json=body, headers=headers)
    result = await response.json()
    assert result["type"] == "create_entry", result
    data = {"grant_type": "authorization_code", "client_id": client_id, "code": result["result"]}
    if verifier is not None:
        data["code_verifier"] = verifier
    response = await runtime.client.post("/auth/token", data=data)
    tokens = await response.json()
    if verifier == PKCE_VERIFIER:
        assert response.status == 200, tokens
        assert tokens["ha_auth_provider"] == "tsidp"
        assert tokens["refresh_token"] and tokens["access_token"]
        assert len(runtime.owner.refresh_tokens) == 1
        token = next(iter(runtime.owner.refresh_tokens.values()))
        assert token.user is runtime.owner
    else:
        assert response.status == 400, tokens
        assert tokens["error"] in {"invalid_request", "invalid_grant"}
        assert "access_token" not in tokens and "refresh_token" not in tokens
        assert not runtime.owner.refresh_tokens
    # Native codes and our browser ticket are both one-use, even after failure.
    assert runtime.retrieve_code(client_id, result["result"]) is None
    replay = await runtime.client.post("/auth/login_flow", json=body, headers=headers)
    assert (await replay.json())["reason"] == "restart_sso"
    assert len(await runtime.hass.auth.async_get_users()) == 1


@pytest.mark.parametrize("runtime", [None, "headers", "headers_frozen"], indirect=True)
async def test_native_non_pkce_client_still_exchanges_code(runtime):
    client_id, redirect_uri = "https://home-assistant.io/android", "homeassistant://auth-callback"
    headers, body = login_request(runtime, client_id, redirect_uri)
    response = await runtime.client.post("/auth/login_flow", json=body, headers=headers)
    result = await response.json()
    assert result["type"] == "create_entry", result
    response = await runtime.client.post(
        "/auth/token",
        data={"grant_type": "authorization_code", "client_id": client_id, "code": result["result"]},
    )
    tokens = await response.json()
    assert response.status == 200, tokens
    assert tokens["ha_auth_provider"] == "tsidp"
    assert len(runtime.owner.refresh_tokens) == 1


@pytest.mark.skipif(not HAS_NATIVE_PKCE, reason="Native Core has no PKCE support")
async def test_native_pkce_survives_entire_oidc_handoff_and_mfa(runtime):
    """Mock only the IdP; real HA HTTP/provider/MFA/code/token processing."""
    runtime.hass.auth._mfa_modules["test"] = TestMFA(runtime.hass, {"type": "test"})
    client_id, redirect_uri = ORIGIN + "/", ORIGIN + "/?auth_callback=1"
    query = urlencode(
        {"client_id": client_id, "redirect_uri": redirect_uri, "state": "a+b/=", **PKCE}
    )
    response = await runtime.client.get(
        URL("/auth/tsidp/start?" + query, encoded=True), allow_redirects=False
    )
    assert response.status == 302
    assert response.headers["Location"] == runtime.authorization.authorization_url
    browser = response.cookies[BROWSER_COOKIE].value
    headers = {"Origin": ORIGIN, "Cookie": f"{BROWSER_COOKIE}={browser}"}
    response = await runtime.client.get(
        "/auth/tsidp/callback?" + urlencode({"state": runtime.authorization.state, "code": "test"}),
        headers=headers,
        allow_redirects=False,
    )
    assert response.status == 302
    assert response.headers["Location"] == "/auth/authorize?" + query + "&tsidp_resume=1"
    ticket = response.cookies[TICKET_COOKIE].value
    headers["Cookie"] += f"; {TICKET_COOKIE}={ticket}"
    response = await runtime.client.post(
        "/auth/login_flow",
        headers=headers,
        json={
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "handler": ["tsidp", None],
            **PKCE,
        },
    )
    result = await response.json()
    assert result["type"] == "form", result
    assert result["step_id"] == "mfa"
    assert not runtime.owner.refresh_tokens
    response = await runtime.client.post(
        "/auth/login_flow/" + result["flow_id"],
        headers={"Origin": ORIGIN},
        json={"client_id": client_id, "code": "test-only-code"},
    )
    result = await response.json()
    assert result["type"] == "create_entry", result
    response = await runtime.client.post(
        "/auth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": result["result"],
            "code_verifier": PKCE_VERIFIER,
        },
    )
    assert response.status == 200, await response.json()
    assert len(runtime.owner.refresh_tokens) == 1
    assert len(await runtime.hass.auth.async_get_users()) == 1


@pytest.mark.parametrize("runtime", ["headers_setup", "headers_setup_frozen"], indirect=True)
@pytest.mark.parametrize("mfa", [False, True])
async def test_headers_entire_handoff_native_tokens_and_optional_mfa(runtime, mfa):
    """Only the transport is simulated: real HA creates credentials, MFA and tokens."""
    if mfa:
        runtime.hass.auth._mfa_modules["test"] = TestMFA(runtime.hass, {"type": "test"})
    client_id, redirect_uri = ORIGIN + "/", ORIGIN + "/?auth_callback=1"
    pkce = PKCE if HAS_NATIVE_PKCE else {}
    query = urlencode(
        {"client_id": client_id, "redirect_uri": redirect_uri, "state": "a+b/=", **pkce}
    )
    response = await runtime.client.get(
        URL("/auth/tsidp/start?" + query, encoded=True),
        headers={LOGIN_HEADER: runtime.identity.subject},
        allow_redirects=False,
    )
    assert response.status == 302
    assert response.headers["Location"] == "/auth/authorize?" + query + "&tsidp_resume=1"
    browser = response.cookies[BROWSER_COOKIE].value
    ticket = response.cookies[TICKET_COOKIE].value
    assert response.cookies[TICKET_COOKIE]["secure"]
    assert response.cookies[TICKET_COOKIE]["httponly"]
    assert response.cookies[TICKET_COOKIE]["samesite"] == "Lax"
    runtime.oidc.begin.assert_not_awaited()
    runtime.oidc.complete.assert_not_awaited()
    response = await runtime.client.get("/auth/tsidp/callback?state=x&code=x")
    assert response.status == 404  # Header mode installs no OIDC callback.
    headers = {
        "Origin": ORIGIN,
        LOGIN_HEADER: runtime.identity.subject,
        "Cookie": f"{BROWSER_COOKIE}={browser}; {TICKET_COOKIE}={ticket}",
    }
    body = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "handler": ["tsidp", None],
        **pkce,
    }
    response = await runtime.client.post("/auth/login_flow", headers=headers, json=body)
    result = await response.json()
    if mfa:
        assert result["type"] == "form" and result["step_id"] == "mfa", result
        assert not runtime.owner.refresh_tokens
        response = await runtime.client.post(
            "/auth/login_flow/" + result["flow_id"],
            headers={"Origin": ORIGIN},
            json={"client_id": client_id, "code": "test-only-code"},
        )
        result = await response.json()
    assert result["type"] == "create_entry", result
    response = await runtime.client.post(
        "/auth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": result["result"],
            **({"code_verifier": PKCE_VERIFIER} if pkce else {}),
        },
    )
    tokens = await response.json()
    assert response.status == 200, tokens
    assert tokens["ha_auth_provider"] == "tsidp"
    assert tokens["refresh_token"] and tokens["access_token"]
    assert len(runtime.owner.refresh_tokens) == 1
    assert len(await runtime.hass.auth.async_get_users()) == 1
    credentials = await runtime.provider.async_credentials()
    assert len(credentials) == 1
    assert credentials[0].data == {
        "issuer": SERVE_ISSUER,
        "subject": runtime.identity.subject,
    }
    response = await runtime.client.post("/auth/login_flow", headers=headers, json=body)
    assert (await response.json())["reason"] == "restart_sso"


@pytest.mark.parametrize("runtime", ["headers_setup_frozen"], indirect=True)
@pytest.mark.parametrize(
    "headers",
    [
        {},
        {LOGIN_HEADER: "unmapped@example.test"},
        {LOGIN_HEADER: "OWNER@example.test"},
        [(LOGIN_HEADER, "owner@example.test"), (LOGIN_HEADER, "owner@example.test")],
    ],
)
async def test_header_absent_tagged_unmapped_or_duplicated_returns_password(runtime, headers):
    query = urlencode({"client_id": ORIGIN + "/", "redirect_uri": ORIGIN + "/?auth_callback=1"})
    response = await runtime.client.get(
        URL("/auth/tsidp/start?" + query, encoded=True), headers=headers, allow_redirects=False
    )
    assert response.status == 302
    assert response.headers["Location"] == "/auth/authorize?" + query + "&tsidp_local=1"
    assert response.cookies[TICKET_COOKIE]["max-age"] == "0"
    assert not runtime.sessions._tickets
    assert not await runtime.provider.async_credentials()
    assert not runtime.owner.refresh_tokens
    response = await runtime.client.get(
        URL(response.headers["Location"], encoded=True), allow_redirects=False
    )
    assert response.status == 200  # Local authorize HTML, not another SSO redirect.
    assert response.cookies[MODE_COOKIE].value == "local"
    response = await runtime.client.get(
        "/auth/providers", headers={"Cookie": f"{MODE_COOKIE}=local"}
    )
    assert [provider["type"] for provider in (await response.json())["providers"]] == [
        "homeassistant"
    ]
    response = await runtime.client.post(
        "/auth/login_flow",
        headers={"Origin": ORIGIN},
        json={
            "client_id": ORIGIN + "/",
            "redirect_uri": ORIGIN + "/?auth_callback=1",
            "handler": ["homeassistant", None],
        },
    )
    assert (await response.json())["type"] == "form"


@pytest.mark.parametrize("runtime", ["headers"], indirect=True)
async def test_header_mapped_user_disabled_after_ticket_cannot_finish(runtime):
    mapped = await runtime.hass.auth.async_create_user("Mapped non-owner")
    runtime.provider.bindings[(SERVE_ISSUER, runtime.identity.subject)] = mapped.id
    runtime.owner = mapped
    headers, body = login_request(runtime, ORIGIN + "/", ORIGIN + "/?auth_callback=1")
    await runtime.hass.auth.async_deactivate_user(mapped)
    response = await runtime.client.post("/auth/login_flow", headers=headers, json=body)
    result = await response.json()
    assert result["type"] == "abort" and result["reason"] == "invalid_auth", result
    assert not await runtime.provider.async_credentials()


@pytest.mark.parametrize("runtime", ["headers"], indirect=True)
async def test_headers_cannot_silently_authorize_arbitrary_indieauth_client(runtime):
    query = urlencode(
        {
            "client_id": "https://attacker.test/",
            "redirect_uri": "https://attacker.test/callback",
        }
    )
    response = await runtime.client.get(
        "/auth/tsidp/start?" + query,
        headers={LOGIN_HEADER: runtime.identity.subject},
        allow_redirects=False,
    )
    assert response.status == 403
    assert not runtime.sessions._tickets
    assert not await runtime.provider.async_credentials()


@pytest.mark.parametrize("runtime", ["headers"], indirect=True)
@pytest.mark.parametrize(
    "changes",
    [
        {"client_id": "https://home-assistant.io/android"},
        {"redirect_uri": "homeassistant://auth-callback"},
        {"client_id": "https://attacker.test/", "redirect_uri": "https://attacker.test/callback"},
    ],
)
async def test_header_ticket_cannot_switch_native_client_or_redirect(runtime, changes):
    headers, body = login_request(runtime, ORIGIN + "/", ORIGIN + "/?auth_callback=1")
    response = await runtime.client.post(
        "/auth/login_flow", headers=headers, json={**body, **changes}
    )
    result = await response.json()
    assert result["type"] == "abort" and result["reason"] == "invalid_auth", result
    assert not await runtime.provider.async_credentials()


@pytest.mark.parametrize("runtime", ["headers"], indirect=True)
@pytest.mark.parametrize("kind", ["missing", "changed", "duplicate", "untrusted_peer"])
async def test_header_identity_rechecked_on_native_post_even_with_valid_ticket(runtime, kind):
    headers, body = login_request(runtime, ORIGIN + "/", ORIGIN + "/?auth_callback=1")
    if kind == "missing":
        del headers[LOGIN_HEADER]
    elif kind == "changed":
        headers[LOGIN_HEADER] = "attacker@example.test"
    elif kind == "duplicate":
        headers = [*headers.items(), (LOGIN_HEADER, runtime.identity.subject)]
    else:
        runtime.provider.header_identity = HeaderIdentity(("192.0.2.1",))
        headers["X-Forwarded-For"] = "192.0.2.1"
    response = await runtime.client.post("/auth/login_flow", headers=headers, json=body)
    result = await response.json()
    assert result["type"] == "abort" and result["reason"] == "invalid_auth", result
    assert not runtime.owner.refresh_tokens
    assert not await runtime.provider.async_credentials()


@pytest.mark.parametrize("runtime", ["headers"], indirect=True)
async def test_oidc_credentials_and_refresh_session_survive_header_mode(runtime):
    # Existing credentials have the same provider type/id, but are not silently
    # repurposed as header identities or removed when the mode changes.
    credential = runtime.provider.async_create_credentials(
        {"issuer": ISSUER, "subject": "old-oidc-subject"}
    )
    await runtime.hass.auth.async_link_user(runtime.owner, credential)
    refresh = await runtime.hass.auth.async_create_refresh_token(
        runtime.owner, ORIGIN + "/", credential=credential
    )
    headers, body = login_request(runtime, ORIGIN + "/", ORIGIN + "/?auth_callback=1")
    response = await runtime.client.post("/auth/login_flow", headers=headers, json=body)
    assert (await response.json())["type"] == "create_entry"
    assert len(await runtime.provider.async_credentials()) == 2
    response = await runtime.client.post(
        "/auth/token",
        data={
            "grant_type": "refresh_token",
            "client_id": ORIGIN + "/",
            "refresh_token": refresh.token,
        },
    )
    tokens = await response.json()
    assert response.status == 200, tokens
    assert tokens["access_token"]
    assert runtime.hass.auth.async_get_refresh_token(refresh.id) is refresh


async def test_exact_bundled_frontend_html_bridge_contract(runtime):
    """Read the real installed frontend, not our simplified HTML fixture."""
    package = pytest.importorskip("hass_frontend", reason="Install the audited frontend wheel")
    expected_version = {
        "2026.9.3": "20260826.7",
        "2026.10.1": "20260930.3",
        "2026.10.2": "20260930.4",
    }[__version__]
    assert metadata.version("home-assistant-frontend") == expected_version
    html = (Path(package.__file__).parent / "authorize.html").read_text()
    assert 'import("/frontend_latest/authorize.' in html
    native = web.Response(text=html, content_type="text/html")
    from custom_components.tsidp.ha_adapter import _authorize_html

    response = await _authorize_html(runtime.handle, native)
    assert response.text == html.replace("<head>", "<head>" + BRIDGE_SCRIPT, 1)
    assert response.text.index(BRIDGE_SCRIPT) < response.text.index('import("/frontend_latest/')


@pytest.mark.parametrize("runtime", ["frozen"], indirect=True)
async def test_future_core_same_contracts_installs_and_clears_prior_repair(runtime, monkeypatch):
    """No calendar gate, including at the actual YAML/Repairs integration edge."""
    from homeassistant import const
    from homeassistant.helpers import issue_registry as ir

    from custom_components.tsidp import COMPATIBILITY_ISSUE

    runtime.handle.disable()
    monkeypatch.setattr(const, "__version__", "2027.1.0")
    ir.async_create_issue(
        runtime.hass,
        "tsidp",
        COMPATIBILITY_ISSUE,
        is_fixable=False,
        is_persistent=True,
        severity=ir.IssueSeverity.ERROR,
        translation_key="runtime_compatibility",
        translation_placeholders={"reason": "old failure"},
    )
    config = {
        "tsidp": {
            "auth_mode": "headers",
            "base_url": ORIGIN,
            "trusted_proxies": ["127.0.0.1"],
            "users": {"owner@example.test": runtime.owner.id},
        }
    }
    assert await async_setup(runtime.hass, config) is True
    installed = runtime.hass.data["tsidp"]
    try:
        assert runtime.hass.auth.get_auth_provider("tsidp", None) is installed.provider
        assert ir.async_get(runtime.hass).async_get_issue("tsidp", COMPATIBILITY_ISSUE) is None
    finally:
        installed.disable()


@pytest.mark.parametrize("runtime", ["frozen"], indirect=True)
async def test_changed_native_contract_keeps_component_loaded_with_real_ha_repair(
    runtime, monkeypatch
):
    from homeassistant.helpers import issue_registry as ir

    from custom_components.tsidp import COMPATIBILITY_ISSUE, ha_adapter

    runtime.handle.disable()

    def incompatible():
        raise RuntimeError("Changed native security contract: MFA")

    monkeypatch.setattr(ha_adapter, "check_runtime_contracts", incompatible)
    config = {
        "tsidp": {
            "auth_mode": "headers",
            "base_url": ORIGIN,
            "trusted_proxies": ["127.0.0.1"],
            "users": {"owner@example.test": runtime.owner.id},
        }
    }
    assert await async_setup(runtime.hass, config) is True
    assert "compatibility_error" in runtime.hass.data["tsidp"]
    assert runtime.hass.auth.get_auth_provider("tsidp", None) is None
    assert runtime.hass.auth.get_auth_provider("homeassistant", None) is not None
    issue = ir.async_get(runtime.hass).async_get_issue("tsidp", COMPATIBILITY_ISSUE)
    assert issue is not None and issue.is_persistent
    assert issue.severity is ir.IssueSeverity.ERROR
    for route in runtime.hass.http.app.router.routes():
        path = route.get_info().get("path")
        if route.method == "GET" and path is not None and path in runtime.originals:
            assert route.handler is runtime.originals[path]
