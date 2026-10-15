"""Optional real HA 2026.9.3 core smoke; run with the isolated Python 3.14 venv.

This uses actual AuthManager, provider base, credential store, HTTP login-flow
views and MFA processing. It is not a browser or Companion app E2E test.
"""

# ruff: noqa: E402
from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

pytest.importorskip("homeassistant", reason="Optional isolated HA runtime smoke")

import voluptuous as vol
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from homeassistant.auth import InvalidAuthError, auth_manager_from_config
from homeassistant.auth.mfa_modules import MultiFactorAuthModule
from homeassistant.components.auth import _create_auth_code_store
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

from custom_components.tsidp.ha_adapter import (
    BROWSER_COOKIE,
    MODE_COOKIE,
    TICKET_COOKIE,
    async_install,
)
from custom_components.tsidp.oidc import Identity
from custom_components.tsidp.session import SessionManager, new_browser_secret

ORIGIN = "https://ha.example.test"
ISSUER = "https://idp.example.test"


@pytest.fixture
async def runtime(tmp_path, request):
    assert __version__ == "2026.9.3", "Extend the audit before changing the runtime target"
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

    async def native_authorize(_request):
        return web.Response(text="native authorize page")

    app.router.add_get("/auth/authorize", native_authorize)
    originals = {
        route.get_info().get("path"): route.handler
        for route in app.router.routes()
        if route.method == "GET"
    }
    if getattr(request, "param", None) == "frozen":
        # Mirror HomeAssistantHTTP.start: middleware/application freeze, but
        # integrations may still register new routes using the public API.
        app.router.freeze = lambda: None
        app.freeze()
        assert app.frozen and not app.router.frozen
    sessions = SessionManager()
    identity = Identity(issuer=ISSUER, subject="stable-owner-sub", name="Ignored", email=None)
    handle = await async_install(
        hass,
        oidc=object(),
        sessions=sessions,
        bindings={(ISSUER, identity.subject): owner.id},
        callback_url=ORIGIN + "/auth/tsidp/callback",
    )
    client = TestClient(TestServer(app))
    await client.start_server()
    yield SimpleNamespace(
        hass=hass,
        owner=owner,
        sessions=sessions,
        identity=identity,
        provider=handle.provider,
        client=client,
        retrieve_code=retrieve_code,
        handle=handle,
        originals=originals,
    )
    await client.close()
    handle.disable()
    await hass.async_stop()


def login_request(runtime, client_id, redirect_uri):
    browser = new_browser_secret()
    path = "/auth/authorize?" + urlencode(
        {"client_id": client_id, "redirect_uri": redirect_uri, "state": "opaque+state/="}
    )
    ticket = runtime.sessions.issue_ticket(runtime.identity, browser, runtime.owner.id, path)
    headers = {"Origin": ORIGIN, "Cookie": f"{BROWSER_COOKIE}={browser}; {TICKET_COOKIE}={ticket}"}
    body = {"client_id": client_id, "redirect_uri": redirect_uri, "handler": ["tsidp", None]}
    return headers, body


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
    credential = runtime.retrieve_code(client_id, code)
    assert credential is not None
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
    response = await runtime.client.get("/auth/authorize?" + query, allow_redirects=False)
    assert response.status == 302
    assert response.headers["Location"].startswith("/auth/tsidp/start?")
    response = await runtime.client.get("/auth/authorize?" + query + "&tsidp_local=1")
    assert response.status == 200
    assert await response.text() == "native authorize page"
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
    assert await response.text() == "native authorize page"


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
