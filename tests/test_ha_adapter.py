"""Isolated adapter tests, not a real Home Assistant/mobile end-to-end test."""

from __future__ import annotations

import importlib
import sys
from contextvars import ContextVar
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request
from yarl import URL

from custom_components.tsidp.ha_adapter import (
    BROWSER_COOKIE,
    LOCAL_FLAG,
    MODE_COOKIE,
    RESUME_FLAG,
    TICKET_COOKIE,
    AdapterHandle,
    async_install,
    make_middleware,
)
from custom_components.tsidp.oidc import Authorization, Identity
from custom_components.tsidp.session import SessionError, SessionManager, new_browser_secret

ISSUER = "https://idp.example.test"
ORIGIN = "https://ha.example.test"
CALLBACK = ORIGIN + "/auth/tsidp/callback"
QUERY = (
    "client_id=https%3A%2F%2Fhome-assistant.io%2Fandroid&"
    "redirect_uri=homeassistant%3A%2F%2Fauth-callback&state=a%2Bb%2Fc%3D&opaque=x%2Fy%3Dz"
)


@pytest.fixture
def ha(monkeypatch):
    """Scope HA imports strictly to this fixture; never shadow HA for other tests."""

    def module(name, **attributes):
        result = ModuleType(name)
        result.__dict__.update(attributes)
        monkeypatch.setitem(sys.modules, name, result)
        return result

    class InvalidAuthError(Exception):
        pass

    class AuthProvider:
        def __init__(self, hass, store, config):
            self.hass, self.store, self.config = hass, store, config

        async def async_initialize(self):
            pass

        async def async_credentials(self):
            return self.store.credentials

        def async_create_credentials(self, data):
            return SimpleNamespace(data=data)

    class LoginFlow:
        def __init__(self, provider):
            self._auth_provider = provider
            self._auth_manager = provider.hass.auth
            self.context = {"redirect_uri": "homeassistant://auth-callback"}

        def async_abort(self, *, reason):
            return {"type": "abort", "reason": reason}

        async def async_finish(self, result):
            return {"type": "create_entry", "data": result}

    current_request = ContextVar("test_request", default=None)
    module("homeassistant")
    module("homeassistant.const", __version__="2026.9.3")
    module("homeassistant.auth", InvalidAuthError=InvalidAuthError)
    module("homeassistant.auth.providers", AuthProvider=AuthProvider, LoginFlow=LoginFlow)
    module("homeassistant.helpers")
    module("homeassistant.helpers.http", current_request=current_request)
    module("homeassistant.components")
    module("homeassistant.components.http", HomeAssistantView=type("HomeAssistantView", (), {}))
    indieauth = SimpleNamespace(
        verify_client_id=lambda _: True, verify_redirect_uri=AsyncMock(return_value=True)
    )
    module("homeassistant.components.auth", indieauth=indieauth)
    names = ("custom_components.tsidp.provider", "custom_components.tsidp.views")
    for name in names:
        monkeypatch.delitem(sys.modules, name, raising=False)
    provider = importlib.import_module(names[0])
    views = importlib.import_module(names[1])
    user = SimpleNamespace(id="owner-id", is_active=True, system_generated=False)
    store = SimpleNamespace(credentials=[])
    providers = {("homeassistant", None): object()}
    auth = SimpleNamespace(
        _providers=providers,
        _store=store,
        get_auth_provider=lambda *key: providers.get(key),
        async_get_user=AsyncMock(return_value=user),
        async_get_user_by_credentials=AsyncMock(return_value=user),
        async_link_user=AsyncMock(),
    )
    app = web.Application()
    hass = SimpleNamespace(
        auth=auth, http=SimpleNamespace(app=app, register_view=lambda view: None)
    )
    yield SimpleNamespace(
        hass=hass,
        provider=provider,
        views=views,
        request=current_request,
        indieauth=indieauth,
        user=user,
        error=InvalidAuthError,
    )
    for name in names:
        sys.modules.pop(name, None)


async def client_for(handle):
    app = web.Application(middlewares=[make_middleware(handle)])

    async def authorize(request):
        return web.Response(text="native authorize page")

    async def providers(request):
        return web.json_response(
            {
                "providers": [
                    {"type": "tsidp", "id": None},
                    {"type": "trusted_networks", "id": None},
                    {"type": "homeassistant", "id": None},
                ],
                "preselect_remember_me": True,
            }
        )

    app.router.add_get("/auth/authorize", authorize)
    app.router.add_get("/auth/providers", providers)
    app.router.add_post("/auth/token", authorize)
    app.router.add_post("/auth/authorize", authorize)
    client = TestClient(TestServer(app))
    await client.start_server()
    return client


async def test_narrow_bridge_keeps_raw_mobile_query():
    client = await client_for(SimpleNamespace(enabled=True))
    try:
        response = await client.get(
            URL("/auth/authorize?" + QUERY, encoded=True), allow_redirects=False
        )
        assert response.status == 302
        assert response.headers["Location"] == "/auth/tsidp/start?" + QUERY
        for path in ("/auth/token", "/auth/authorize"):
            response = await client.post(path)
            assert response.status == 200
            assert await response.text() == "native authorize page"
    finally:
        await client.close()


@pytest.mark.parametrize("flag,mode", [(LOCAL_FLAG, "local"), (RESUME_FLAG, "oidc")])
async def test_stock_page_bypasses_set_secure_scoped_mode(flag, mode):
    client = await client_for(SimpleNamespace(enabled=True))
    try:
        response = await client.get(f"/auth/authorize?{QUERY}&{flag}=1")
        assert await response.text() == "native authorize page"
        assert response.cookies[MODE_COOKIE].value == mode
        assert response.cookies[MODE_COOKIE]["secure"]
        assert response.cookies[MODE_COOKIE]["httponly"]
        assert response.cookies[MODE_COOKIE]["samesite"] == "Lax"
        assert response.cookies[MODE_COOKIE]["path"] == "/"
        if mode == "local":
            assert response.cookies[TICKET_COOKIE]["max-age"] == "0"
    finally:
        await client.close()


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("local", ["homeassistant", "trusted_networks"]),
        ("oidc", ["tsidp", "trusted_networks", "homeassistant"]),
        ("", ["tsidp", "trusted_networks", "homeassistant"]),
    ],
)
async def test_provider_order_is_request_local(mode, expected):
    client = await client_for(SimpleNamespace(enabled=True))
    try:
        response = await client.get("/auth/providers", headers={"Cookie": f"{MODE_COOKIE}={mode}"})
        result = await response.json()
        assert [p["type"] for p in result["providers"]] == expected
        assert result["preselect_remember_me"] is True
        if mode:
            assert response.cookies[MODE_COOKIE]["max-age"] == "0"
    finally:
        await client.close()


async def test_disabled_bridge_passthrough():
    client = await client_for(SimpleNamespace(enabled=False))
    try:
        response = await client.get("/auth/authorize?" + QUERY)
        assert response.status == 200
    finally:
        await client.close()


async def test_install_and_disable_only_own_provider(ha):
    handle = await async_install(
        ha.hass, oidc=object(), sessions=SessionManager(), bindings={}, callback_url=CALLBACK
    )
    assert len(ha.hass.http.app.middlewares) == 1
    assert list(ha.hass.auth._providers) == [("homeassistant", None), ("tsidp", None)]
    handle.disable()
    assert not handle.enabled
    assert list(ha.hass.auth._providers) == [("homeassistant", None)]


async def test_install_rejects_frozen_app_and_unknown_version(ha):
    ha.hass.http.app.freeze()
    with pytest.raises(RuntimeError, match="frozen HTTP router"):
        await async_install(
            ha.hass, oidc=object(), sessions=SessionManager(), bindings={}, callback_url=CALLBACK
        )
    sys.modules["homeassistant.const"].__version__ = "2026.10.0"
    with pytest.raises(RuntimeError, match="2026.9.3"):
        await async_install(
            ha.hass, oidc=object(), sessions=SessionManager(), bindings={}, callback_url=CALLBACK
        )


async def test_callback_resumes_native_flow_and_credential_links_existing_owner(ha):
    sessions = SessionManager()
    identity = Identity(
        issuer=ISSUER, subject="stable-sub", name="Owner", email="owner@example.test"
    )
    authorization = Authorization(
        state=new_browser_secret(),
        nonce=new_browser_secret(),
        code_verifier=new_browser_secret(),
        authorization_url=ISSUER + "/authorize",
    )
    oidc = SimpleNamespace(
        begin=AsyncMock(return_value=authorization), complete=AsyncMock(return_value=identity)
    )
    bindings = {(ISSUER, "stable-sub"): "owner-id"}
    provider = ha.provider.TsidpAuthProvider(
        ha.hass, ha.hass.auth._store, sessions, bindings, ORIGIN
    )
    handle = AdapterHandle(ha.hass, provider)
    start = await ha.views.StartView(handle, oidc, sessions).get(
        make_mocked_request("GET", "/auth/tsidp/start?" + QUERY)
    )
    browser = start.cookies[BROWSER_COOKIE].value
    response = await ha.views.CallbackView(handle, oidc, sessions, bindings).get(
        make_mocked_request(
            "GET",
            "/auth/tsidp/callback?state=" + authorization.state + "&code=test",
            headers={"Cookie": f"{BROWSER_COOKIE}={browser}"},
        )
    )
    assert response.status == 302
    assert response.headers["Location"] == "/auth/authorize?" + QUERY + "&tsidp_resume=1"
    ticket = response.cookies[TICKET_COOKIE].value
    request = make_mocked_request(
        "POST",
        "/auth/login_flow",
        headers={
            "Origin": ORIGIN,
            "Cookie": f"{BROWSER_COOKIE}={browser}; {TICKET_COOKIE}={ticket}",
        },
    )
    request.json = AsyncMock(
        return_value={
            "client_id": "https://home-assistant.io/android",
            "redirect_uri": "homeassistant://auth-callback",
        }
    )
    token = ha.request.set(request)
    try:
        result = await ha.provider.TsidpLoginFlow(provider).async_step_init()
        assert result["type"] == "create_entry"
        # A mapping is essential: a raw Credentials result bypasses core MFA.
        assert result["data"] == {
            "issuer": ISSUER,
            "subject": "stable-sub",
            "ha_user_id": "owner-id",
        }
        credential = await provider.async_get_or_create_credentials(result["data"])
        ha.hass.auth.async_link_user.assert_awaited_once_with(ha.user, credential)
        assert (await ha.provider.TsidpLoginFlow(provider).async_step_init())["type"] == "abort"
    finally:
        ha.request.reset(token)
    with pytest.raises(SessionError):
        sessions.consume_state(authorization.state, browser)


async def test_provider_rejects_wrong_origin_without_consuming_ticket(ha):
    sessions = SessionManager()
    browser = new_browser_secret()
    identity = Identity(issuer=ISSUER, subject="s", name=None, email=None)
    ticket = sessions.issue_ticket(identity, browser, "owner-id")
    provider = ha.provider.TsidpAuthProvider(
        ha.hass, ha.hass.auth._store, sessions, {(ISSUER, "s"): "owner-id"}, ORIGIN
    )
    request = make_mocked_request(
        "POST",
        "/auth/login_flow",
        headers={
            "Origin": "https://attacker.test",
            "Cookie": f"{BROWSER_COOKIE}={browser}; {TICKET_COOKIE}={ticket}",
        },
    )
    token = ha.request.set(request)
    try:
        assert (await ha.provider.TsidpLoginFlow(provider).async_step_init())["type"] == "abort"
    finally:
        ha.request.reset(token)
    assert sessions.consume_ticket(ticket, browser).ha_user_id == "owner-id"


async def test_invalid_client_rejected_before_oidc_and_no_new_user(ha):
    oidc = SimpleNamespace(begin=AsyncMock())
    ha.indieauth.verify_redirect_uri.return_value = False
    handle = AdapterHandle(ha.hass, SimpleNamespace(origin=ORIGIN))
    response = await ha.views.StartView(handle, oidc, SessionManager()).get(
        make_mocked_request("GET", "/auth/tsidp/start?" + QUERY)
    )
    assert response.status == 400
    oidc.begin.assert_not_awaited()


@pytest.mark.parametrize(
    "field,value",
    [
        ("client_id", "https://attacker.test/"),
        ("redirect_uri", "https://attacker.test/callback"),
    ],
)
async def test_ticket_cannot_authorize_another_client_or_redirect(ha, field, value):
    sessions = SessionManager()
    browser = new_browser_secret()
    identity = Identity(issuer=ISSUER, subject="s", name=None, email=None)
    ticket = sessions.issue_ticket(identity, browser, "owner-id", "/auth/authorize?" + QUERY)
    provider = ha.provider.TsidpAuthProvider(
        ha.hass, ha.hass.auth._store, sessions, {(ISSUER, "s"): "owner-id"}, ORIGIN
    )
    body = {
        "client_id": "https://home-assistant.io/android",
        "redirect_uri": "homeassistant://auth-callback",
    }
    body[field] = value
    request = SimpleNamespace(
        method="POST",
        path="/auth/login_flow",
        headers={"Origin": ORIGIN},
        cookies={BROWSER_COOKIE: browser, TICKET_COOKIE: ticket},
        json=AsyncMock(return_value=body),
    )
    token = ha.request.set(request)
    try:
        assert (await ha.provider.TsidpLoginFlow(provider).async_step_init())["type"] == "abort"
    finally:
        ha.request.reset(token)
    with pytest.raises(SessionError):
        sessions.consume_ticket(ticket, browser)
    ha.hass.auth.async_link_user.assert_not_awaited()


async def test_partial_registration_failure_restores_native_auth(ha):
    ha.hass.http.register_view = AsyncMock()  # Replace below with a synchronous failure.

    def fail(_):
        raise RuntimeError("simulated registration failure")

    ha.hass.http.register_view = fail
    with pytest.raises(RuntimeError, match="simulated"):
        await async_install(
            ha.hass, oidc=object(), sessions=SessionManager(), bindings={}, callback_url=CALLBACK
        )
    assert len(ha.hass.http.app.middlewares) == 0
    assert list(ha.hass.auth._providers) == [("homeassistant", None)]


async def test_attacker_indieauth_client_rejected_before_oidc_begin(ha):
    """IndieAuth-valid third-party clients must not get silent owner consent."""
    oidc = SimpleNamespace(begin=AsyncMock())
    handle = AdapterHandle(ha.hass, SimpleNamespace(origin=ORIGIN))
    response = await ha.views.StartView(handle, oidc, SessionManager()).get(
        make_mocked_request(
            "GET",
            "/auth/tsidp/start?"
            "client_id=https%3A%2F%2Fattacker.test%2F&"
            "redirect_uri=https%3A%2F%2Fattacker.test%2Fcallback&state=untrusted",
        )
    )
    assert response.status == 403
    assert "tsidp_local=1" in response.text
    ha.indieauth.verify_redirect_uri.assert_not_awaited()
    oidc.begin.assert_not_awaited()


async def test_forged_ticket_for_matching_attacker_client_still_rejected(ha):
    """Defense in depth: even a trusted-state-store ticket cannot grant unknown apps."""
    sessions = SessionManager()
    browser = new_browser_secret()
    identity = Identity(issuer=ISSUER, subject="s", name=None, email=None)
    path = (
        "/auth/authorize?client_id=https%3A%2F%2Fattacker.test%2F&"
        "redirect_uri=https%3A%2F%2Fattacker.test%2Fcallback&state=untrusted"
    )
    ticket = sessions.issue_ticket(identity, browser, "owner-id", path)
    provider = ha.provider.TsidpAuthProvider(
        ha.hass, ha.hass.auth._store, sessions, {(ISSUER, "s"): "owner-id"}, ORIGIN
    )
    request = SimpleNamespace(
        method="POST",
        path="/auth/login_flow",
        headers={"Origin": ORIGIN},
        cookies={BROWSER_COOKIE: browser, TICKET_COOKIE: ticket},
        json=AsyncMock(
            return_value={
                "client_id": "https://attacker.test/",
                "redirect_uri": "https://attacker.test/callback",
            }
        ),
    )
    flow = ha.provider.TsidpLoginFlow(provider)
    flow.context = {"redirect_uri": "https://attacker.test/callback"}
    token = ha.request.set(request)
    try:
        assert (await flow.async_step_init())["type"] == "abort"
    finally:
        ha.request.reset(token)
    with pytest.raises(SessionError):
        sessions.consume_ticket(ticket, browser)
    ha.hass.auth.async_link_user.assert_not_awaited()


@pytest.mark.parametrize("authorize_count", [0, 2])
async def test_frozen_ha_preflight_rejects_missing_or_duplicate_routes(ha, authorize_count):
    app = ha.hass.http.app

    async def native(_):
        return web.Response(text="native")

    for index in range(authorize_count):
        resource = app.router.add_resource("/auth/authorize", name=f"authorize_{index}")
        resource.add_route("GET", native)
    app.router.add_get("/auth/providers", native)
    app.router.freeze = lambda: None
    app.freeze()
    with pytest.raises(RuntimeError, match="exactly one existing GET route"):
        await async_install(
            ha.hass, oidc=object(), sessions=SessionManager(), bindings={}, callback_url=CALLBACK
        )
    assert list(ha.hass.auth._providers) == [("homeassistant", None)]
    assert len(app.middlewares) == 0


async def test_disable_does_not_overwrite_another_route_wrapper(ha):
    async def original(_):
        return web.Response(text="original")

    async def ours(_):
        return web.Response(text="ours")

    async def later(_):
        return web.Response(text="later")

    route = ha.hass.http.app.router.add_get("/auth/authorize", original)
    route._handler = later
    provider = object()
    ha.hass.auth._providers[("tsidp", None)] = provider
    handle = AdapterHandle(ha.hass, provider, route_handlers=[(route, original, ours)])
    handle.disable()
    assert route.handler is later
    assert ha.hass.auth.get_auth_provider("tsidp", None) is None
