"""Isolated adapter tests, not a real Home Assistant/mobile end-to-end test."""

from __future__ import annotations

import importlib
import sys
from contextvars import ContextVar
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request
from yarl import URL

from custom_components.tsidp import async_setup
from custom_components.tsidp.compatibility import SUPPORTED_HA_VERSIONS
from custom_components.tsidp.ha_adapter import (
    BRIDGE_PATH,
    BRIDGE_SCRIPT,
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
        support_mfa = True

        def __init__(self, hass, store, config):
            self.hass, self.store, self.config = hass, store, config

        async def async_initialize(self):
            pass

        async def async_credentials(self):
            return self.store.credentials

        def async_create_credentials(self, data):
            return SimpleNamespace(data=data, is_new=True)

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
    issues = SimpleNamespace(
        async_create_issue=Mock(),
        async_delete_issue=Mock(),
        IssueSeverity=SimpleNamespace(ERROR="error"),
    )
    module("homeassistant.helpers", issue_registry=issues)
    module("homeassistant.helpers.http", current_request=current_request)
    module(
        "homeassistant.helpers.importlib",
        async_import_module=AsyncMock(side_effect=lambda hass, name: importlib.import_module(name)),
    )
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

    async def link_user(user, credential):
        credential.is_new = False

    store = SimpleNamespace(credentials=[])
    providers = {("homeassistant", None): object()}
    auth = SimpleNamespace(
        _providers=providers,
        _store=store,
        get_auth_provider=lambda *key: providers.get(key),
        async_get_user=AsyncMock(return_value=user),
        async_get_user_by_credentials=AsyncMock(return_value=user),
        async_link_user=AsyncMock(side_effect=link_user),
    )
    app = web.Application()
    hass = SimpleNamespace(
        auth=auth,
        data={},
        http=SimpleNamespace(app=app, register_view=lambda view: None),
        async_add_executor_job=AsyncMock(side_effect=lambda job: job()),
    )
    # Installed official code is checked separately, including in real-HA tests.
    monkeypatch.setattr("custom_components.tsidp.ha_adapter.check_runtime_contracts", lambda: None)
    yield SimpleNamespace(
        hass=hass,
        provider=provider,
        views=views,
        request=current_request,
        indieauth=indieauth,
        user=user,
        error=InvalidAuthError,
        issues=issues,
    )
    for name in names:
        sys.modules.pop(name, None)


async def client_for(handle, *, preselect_remember_me=True, include_tsidp=True):
    app = web.Application(middlewares=[make_middleware(handle)])

    async def authorize(request):
        return web.Response(text="native authorize page")

    async def providers(request):
        return web.json_response(
            {
                "providers": [
                    *([{"type": "tsidp", "id": None}] if include_tsidp else []),
                    {"type": "trusted_networks", "id": None},
                    {"type": "homeassistant", "id": None},
                ],
                "preselect_remember_me": preselect_remember_me,
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
        ("invalid", ["tsidp", "trusted_networks", "homeassistant"]),
        (None, ["tsidp", "trusted_networks", "homeassistant"]),
    ],
)
@pytest.mark.parametrize("native_remember", [False, True])
async def test_provider_order_and_remember_are_request_local(mode, expected, native_remember):
    client = await client_for(SimpleNamespace(enabled=True), preselect_remember_me=native_remember)
    try:
        headers = {} if mode is None else {"Cookie": f"{MODE_COOKIE}={mode}"}
        response = await client.get("/auth/providers", headers=headers)
        result = await response.json()
        assert [p["type"] for p in result["providers"]] == expected
        assert result["preselect_remember_me"] is (native_remember or mode == "oidc")
        if mode in {"local", "oidc"}:
            assert response.cookies[MODE_COOKIE]["max-age"] == "0"
    finally:
        await client.close()


async def test_oidc_mode_without_tsidp_preserves_native_remember_preference():
    client = await client_for(
        SimpleNamespace(enabled=True), preselect_remember_me=False, include_tsidp=False
    )
    try:
        response = await client.get("/auth/providers", headers={"Cookie": f"{MODE_COOKIE}=oidc"})
        result = await response.json()
        assert [p["type"] for p in result["providers"]] == [
            "trusted_networks",
            "homeassistant",
        ]
        assert result["preselect_remember_me"] is False
    finally:
        await client.close()


async def test_disabled_bridge_passthrough():
    client = await client_for(SimpleNamespace(enabled=False))
    try:
        response = await client.get("/auth/authorize?" + QUERY)
        assert response.status == 200
    finally:
        await client.close()


@pytest.mark.parametrize("flag", [LOCAL_FLAG, RESUME_FLAG])
@pytest.mark.parametrize("kind", ["response", "file"])
async def test_authorize_html_gets_only_fixed_external_bridge(ha, tmp_path, flag, kind):
    # The pinned modern loader dynamically imports from an inline classic
    # script, so a deferred bridge is not guaranteed to run before it.
    bootstrap = (
        '<script crossorigin="use-credentials">import("/frontend_latest/authorize.js");</script>'
    )
    html = (
        "<!doctype html><html><head><title>HA</title></head><body>native"
        + bootstrap
        + "</body></html>"
    )
    headers = {
        "X-Core-Security": "preserved",
        "Content-Length": "1",
        "Content-Encoding": "gzip",
        "ETag": '"old-native"',
        "Last-Modified": "Wed, 14 Oct 2026 10:00:00 GMT",
        "Cache-Control": "public, max-age=1000",
    }
    if kind == "file":
        path = tmp_path / "authorize.html"
        path.write_text(html)
        native = web.FileResponse(path, headers=headers)
    else:
        native = web.Response(text=html, content_type="text/html", headers=headers)
    native.set_cookie("native-cookie", "preserved")
    handle = AdapterHandle(ha.hass, object())
    middleware = make_middleware(handle)
    response = await middleware(
        make_mocked_request("GET", f"/auth/authorize?{QUERY}&{flag}=1"),
        AsyncMock(return_value=native),
    )
    assert isinstance(response, web.Response)
    assert response.content_type == "text/html"
    assert response.text == html.replace("<head>", "<head>" + BRIDGE_SCRIPT)
    # No defer, async, or type=module: this external classic script must block
    # parsing before HA can reach its inline import/bootstrap.
    assert BRIDGE_SCRIPT == f'<script src="{BRIDGE_PATH}"></script>'
    assert response.text.index(BRIDGE_SCRIPT) < response.text.index(bootstrap)
    assert QUERY not in response.text
    assert response.headers["X-Core-Security"] == "preserved"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.cookies["native-cookie"].value == "preserved"
    assert response.cookies[MODE_COOKIE].value == ("local" if flag == LOCAL_FLAG else "oidc")
    for header in ("Content-Length", "Content-Encoding", "ETag", "Last-Modified"):
        assert header not in response.headers
    if kind == "file":
        ha.hass.async_add_executor_job.assert_awaited_once()
    else:
        ha.hass.async_add_executor_job.assert_not_awaited()


@pytest.mark.parametrize(
    "method,path,enabled",
    [
        ("GET", "/unrelated?tsidp_resume=1", True),
        ("POST", "/auth/authorize?tsidp_resume=1", True),
        ("GET", "/auth/providers", True),
        ("GET", "/auth/authorize?tsidp_resume=1", False),
    ],
)
async def test_bridge_never_injects_other_pages_methods_or_disabled(ha, method, path, enabled):
    native = web.Response(text="<head></head><body>native</body>", content_type="text/html")
    handle = AdapterHandle(ha.hass, object(), enabled=enabled)
    response = await make_middleware(handle)(
        make_mocked_request(method, path), AsyncMock(return_value=native)
    )
    assert response is native
    assert BRIDGE_PATH not in response.text
    ha.hass.async_add_executor_job.assert_not_awaited()


@pytest.mark.parametrize("kind", ["plain", "json", "stream", "file", "explicit_plain_file"])
async def test_authorize_non_html_unchanged(ha, tmp_path, kind):
    if kind in {"file", "explicit_plain_file"}:
        path = tmp_path / ("authorize.html" if kind == "explicit_plain_file" else "data.bin")
        path.write_text("native")
        native = web.FileResponse(path)
        if kind == "explicit_plain_file":
            native.content_type = "text/plain"
    else:
        native = {
            "plain": web.Response(text="native"),
            "json": web.json_response({"native": True}),
            "stream": web.StreamResponse(),
        }[kind]
    response = await make_middleware(AdapterHandle(ha.hass, object()))(
        make_mocked_request("GET", "/auth/authorize?tsidp_resume=1"),
        AsyncMock(return_value=native),
    )
    assert response is native
    ha.hass.async_add_executor_job.assert_not_awaited()


async def test_public_bridge_asset_no_store_and_disabled(ha):
    handle = AdapterHandle(ha.hass, object())
    asset = ha.views.BridgeView(handle)
    assert asset.url == BRIDGE_PATH and asset.requires_auth is False
    response = await asset.get(make_mocked_request("GET", BRIDGE_PATH))
    assert response.status == 200
    assert response.content_type == "application/javascript"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "pick-auth-provider" in response.text
    assert "restart_sso" in response.text
    ha.hass.async_add_executor_job.assert_awaited_once()
    handle.disable()
    response = await asset.get(make_mocked_request("GET", BRIDGE_PATH))
    assert response.status == 404
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("version", SUPPORTED_HA_VERSIONS)
async def test_install_and_disable_only_own_provider(ha, version):
    sys.modules["homeassistant.const"].__version__ = version
    handle = await async_install(
        ha.hass, oidc=object(), sessions=SessionManager(), bindings={}, callback_url=CALLBACK
    )
    assert len(ha.hass.http.app.middlewares) == 1
    assert list(ha.hass.auth._providers) == [("homeassistant", None), ("tsidp", None)]
    handle.disable()
    assert not handle.enabled
    assert list(ha.hass.auth._providers) == [("homeassistant", None)]


@pytest.mark.parametrize("version", ["2026.10.3", "2026.11.0", "2027.1.0", "2027.1.0b1"])
async def test_future_versions_with_good_contracts_install_with_audit_warning(ha, version, caplog):
    sys.modules["homeassistant.const"].__version__ = version
    config = {
        "tsidp": {
            "auth_mode": "headers",
            "base_url": ORIGIN,
            "trusted_proxies": ["127.0.0.1"],
            "users": {"owner@example.test": "a" * 32},
        }
    }
    assert await async_setup(ha.hass, config) is True
    assert ha.hass.auth.get_auth_provider("tsidp", None) is ha.hass.data["tsidp"].provider
    assert "has not been audited" in caplog.text
    ha.issues.async_create_issue.assert_not_called()
    ha.issues.async_delete_issue.assert_called_once()


async def test_changed_contract_refuses_before_auth_or_http_mutation(ha, monkeypatch):
    def fail_contract():
        raise RuntimeError("Changed runtime contract: native MFA")

    monkeypatch.setattr("custom_components.tsidp.ha_adapter.check_runtime_contracts", fail_contract)
    before = dict(ha.hass.auth._providers)
    with pytest.raises(RuntimeError, match="Changed runtime contract"):
        await async_install(
            ha.hass, oidc=object(), sessions=SessionManager(), bindings={}, callback_url=CALLBACK
        )
    assert ha.hass.auth._providers == before
    assert not ha.hass.http.app.middlewares


async def test_setup_contract_failure_stays_loaded_with_persistent_password_repair(ha, monkeypatch):
    def fail_contract():
        raise RuntimeError("Changed runtime contract: native MFA")

    monkeypatch.setattr("custom_components.tsidp.ha_adapter.check_runtime_contracts", fail_contract)
    config = {
        "tsidp": {
            "auth_mode": "headers",
            "base_url": ORIGIN,
            "trusted_proxies": ["127.0.0.1"],
            "users": {"owner@example.test": "a" * 32},
        }
    }
    assert await async_setup(ha.hass, config) is True
    assert "native MFA" in ha.hass.data["tsidp"]["compatibility_error"]
    assert list(ha.hass.auth._providers) == [("homeassistant", None)]
    assert not ha.hass.http.app.middlewares
    call = ha.issues.async_create_issue.call_args
    assert call.args[1:] == ("tsidp", "runtime_compatibility")
    assert call.kwargs["is_persistent"] is True
    assert call.kwargs["severity"] == "error"
    assert "native MFA" in call.kwargs["translation_placeholders"]["reason"]
    ha.issues.async_delete_issue.assert_not_called()


async def test_install_rejects_frozen_router(ha):
    ha.hass.http.app.freeze()
    with pytest.raises(RuntimeError, match="frozen HTTP router"):
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
        replay = await ha.provider.TsidpLoginFlow(provider).async_step_init()
        assert replay == {"type": "abort", "reason": "restart_sso"}
    finally:
        ha.request.reset(token)
    with pytest.raises(SessionError):
        sessions.consume_state(authorization.state, browser)


@pytest.mark.parametrize(
    "method,path,origin",
    [
        ("POST", "/auth/login_flow", "https://attacker.test"),
        ("GET", "/auth/login_flow", ORIGIN),
        ("POST", "/auth/login_flow/other", ORIGIN),
    ],
)
async def test_provider_rejects_wrong_request_without_consuming_ticket(ha, method, path, origin):
    sessions = SessionManager()
    browser = new_browser_secret()
    identity = Identity(issuer=ISSUER, subject="s", name=None, email=None)
    ticket = sessions.issue_ticket(identity, browser, "owner-id")
    provider = ha.provider.TsidpAuthProvider(
        ha.hass, ha.hass.auth._store, sessions, {(ISSUER, "s"): "owner-id"}, ORIGIN
    )
    request = make_mocked_request(
        method,
        path,
        headers={
            "Origin": origin,
            "Cookie": f"{BROWSER_COOKIE}={browser}; {TICKET_COOKIE}={ticket}",
        },
    )
    token = ha.request.set(request)
    try:
        assert await ha.provider.TsidpLoginFlow(provider).async_step_init() == {
            "type": "abort",
            "reason": "invalid_auth",
        }
    finally:
        ha.request.reset(token)
    assert sessions.consume_ticket(ticket, browser).ha_user_id == "owner-id"


@pytest.mark.parametrize("kind", ["missing", "expired", "browser_mismatch"])
async def test_ticket_session_errors_request_restart_without_authentication(ha, kind):
    now = [100.0]
    sessions = SessionManager(clock=lambda: now[0])
    browser = new_browser_secret()
    identity = Identity(issuer=ISSUER, subject="s", name=None, email=None)
    ticket = sessions.issue_ticket(identity, browser, "owner-id", "/auth/authorize?" + QUERY)
    if kind == "missing":
        ticket = ""
    elif kind == "expired":
        now[0] += 61
    else:
        browser = new_browser_secret()
    provider = ha.provider.TsidpAuthProvider(
        ha.hass, ha.hass.auth._store, sessions, {(ISSUER, "s"): "owner-id"}, ORIGIN
    )
    request = make_mocked_request(
        "POST",
        "/auth/login_flow",
        headers={
            "Origin": ORIGIN,
            "Cookie": f"{BROWSER_COOKIE}={browser}; {TICKET_COOKIE}={ticket}",
        },
    )
    token = ha.request.set(request)
    try:
        assert await ha.provider.TsidpLoginFlow(provider).async_step_init() == {
            "type": "abort",
            "reason": "restart_sso",
        }
    finally:
        ha.request.reset(token)
    ha.hass.auth.async_link_user.assert_not_awaited()
    ha.hass.auth.async_get_user.assert_not_awaited()


async def test_consumed_ticket_missing_authorize_path_remains_invalid_auth(ha):
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
            "Origin": ORIGIN,
            "Cookie": f"{BROWSER_COOKIE}={browser}; {TICKET_COOKIE}={ticket}",
        },
    )
    token = ha.request.set(request)
    try:
        assert await ha.provider.TsidpLoginFlow(provider).async_step_init() == {
            "type": "abort",
            "reason": "invalid_auth",
        }
    finally:
        ha.request.reset(token)
    with pytest.raises(SessionError):
        sessions.consume_ticket(ticket, browser)


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
        assert await ha.provider.TsidpLoginFlow(provider).async_step_init() == {
            "type": "abort",
            "reason": "invalid_auth",
        }
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


async def test_native_provider_must_still_support_mfa_before_registration(ha):
    ha.provider.AuthProvider.support_mfa = False
    with pytest.raises(RuntimeError, match="MFA support"):
        await async_install(
            ha.hass, oidc=object(), sessions=SessionManager(), bindings={}, callback_url=CALLBACK
        )
    assert list(ha.hass.auth._providers) == [("homeassistant", None)]
    assert not ha.hass.http.app.middlewares


@pytest.mark.parametrize("reused", [False, True])
@pytest.mark.parametrize("failure", ["new", "unlinked", "other_user", "inactive", "system"])
async def test_native_mfa_credential_link_invariants(ha, reused, failure):
    data = {"issuer": ISSUER, "subject": "stable", "ha_user_id": ha.user.id}
    provider = ha.provider.TsidpAuthProvider(
        ha.hass, ha.hass.auth._store, SessionManager(), {(ISSUER, "stable"): ha.user.id}, ORIGIN
    )
    if reused:
        ha.hass.auth._store.credentials = [
            SimpleNamespace(data={"issuer": ISSUER, "subject": "stable"}, is_new=False)
        ]
    if failure == "new":
        if reused:
            ha.hass.auth._store.credentials[0].is_new = True
        else:
            ha.hass.auth.async_link_user.side_effect = None
    else:
        linked = SimpleNamespace(id=ha.user.id, is_active=True, system_generated=False)
        if failure == "unlinked":
            linked = None
        elif failure == "other_user":
            linked.id = "another-user"
        elif failure == "inactive":
            linked.is_active = False
        else:
            linked.system_generated = True
        ha.hass.auth.async_get_user_by_credentials.return_value = linked
    with pytest.raises(ha.error, match="active bound account"):
        await provider.async_get_or_create_credentials(data)


@pytest.mark.parametrize(
    "failure", [ImportError("changed adapter import"), TypeError("changed API")]
)
async def test_setup_import_failure_stays_loaded_and_creates_repair(ha, failure):
    sys.modules["homeassistant.helpers.importlib"].async_import_module.side_effect = failure
    assert await async_setup(ha.hass, {"tsidp": {}}) is True
    assert "compatibility_error" in ha.hass.data["tsidp"]
    assert list(ha.hass.auth._providers) == [("homeassistant", None)]
    ha.issues.async_create_issue.assert_called_once()
