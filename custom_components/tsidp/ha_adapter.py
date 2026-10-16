"""Small, version-pinned adapter for HA's private provider registration.

Only the two exact GET paths below are wrapped. HA owns all login-flow, MFA,
authorization-code issuance and token endpoints. Frozen HA apps use exact-route
handler wrappers because HA intentionally leaves its router open for integrations.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aiohttp import web

from .compatibility import SUPPORTED_HA_DESCRIPTION, SUPPORTED_HA_VERSIONS

PROVIDER_TYPE = "tsidp"
BROWSER_COOKIE = "__Host-tsidp-browser"
TICKET_COOKIE = "__Host-tsidp-ticket"
MODE_COOKIE = "__Host-tsidp-mode"
LOCAL_FLAG = "tsidp_local"
RESUME_FLAG = "tsidp_resume"
START_PATH = "/auth/tsidp/start"
AUTHORIZE_PATH = "/auth/authorize"
BRIDGE_PATH = "/auth/tsidp/bridge.js"
BRIDGE_SCRIPT = f'<script src="{BRIDGE_PATH}"></script>'


async def _authorize_html(handle: AdapterHandle, response: web.StreamResponse):
    """Add a fixed self-hosted bridge to native HTML, including HA's FileResponse."""
    if response.status != 200 or response.prepared:
        return response
    encoding = response.charset or "utf-8"
    if isinstance(response, web.FileResponse):
        # FileResponse has no body and defaults to octet-stream before prepare.
        # _path is aiohttp-private: this stays in the version-pinned adapter.
        path = Path(response._path)
        if response.content_type != "text/html" and (
            "Content-Type" in response.headers or path.suffix.lower() not in {".html", ".htm"}
        ):
            return response
        try:
            body = await handle.hass.async_add_executor_job(path.read_bytes)
        except OSError:
            return response
    elif isinstance(response, web.Response) and response.content_type == "text/html":
        body = response.body
        if not isinstance(body, bytes):
            return response
    else:
        return response
    try:
        html = body.decode(encoding)
    except (UnicodeError, LookupError):
        return response
    # HA's pinned loader starts dynamic imports from an inline classic script.
    # Block parsing here: defer could install the bridge after a native auth POST.
    # No user query or other request data is interpolated into HTML or JavaScript.
    head = re.search(r"<head\b[^>]*>", html, re.IGNORECASE)
    position = head.end() if head else 0
    html = html[:position] + BRIDGE_SCRIPT + html[position:]
    headers = response.headers.copy()
    for name in ("Content-Length", "Content-Encoding", "ETag", "Last-Modified"):
        headers.popall(name, None)
    if "Content-Type" not in headers:
        headers["Content-Type"] = "text/html; charset=utf-8"
    result = web.Response(
        body=html.encode(encoding), status=response.status, reason=response.reason, headers=headers
    )
    result.cookies.update(response.cookies)
    return result


def cookie(response: web.StreamResponse, name: str, value: str, ttl: int) -> None:
    """Host-only cookies intentionally require HTTPS, even behind a proxy."""
    response.set_cookie(
        name, value, max_age=ttl, secure=True, httponly=True, samesite="Lax", path="/"
    )


def private_response(response: web.StreamResponse) -> web.StreamResponse:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def redirect(location: str) -> web.Response:
    """Preserve the original encoded HA query, rather than URL-normalizing it."""
    return private_response(web.Response(status=302, headers={"Location": location}))


@dataclass
class AdapterHandle:
    """Deactivation is safe even after aiohttp freezes its middleware list."""

    hass: Any
    provider: Any
    enabled: bool = True
    route_handlers: list[tuple[Any, Any, Any]] = field(default_factory=list)

    def disable(self) -> None:
        self.enabled = False
        for route, original, wrapper in self.route_handlers:
            if route.handler is wrapper:
                route._handler = original  # HA/aiohttp-private, version-pinned here.
        self.route_handlers.clear()
        providers = self.hass.auth._providers  # HA-private, isolated here.
        if providers.get((PROVIDER_TYPE, None)) is self.provider:
            del providers[(PROVIDER_TYPE, None)]


def make_middleware(handle: AdapterHandle):
    """Create the exact-path authorize bridge and request-local provider ordering."""

    @web.middleware
    async def bridge(request: web.Request, handler):
        if not handle.enabled or request.method != "GET":
            return await handler(request)
        if request.path == AUTHORIZE_PATH:
            local = request.query.get(LOCAL_FLAG) == "1"
            resume = request.query.get(RESUME_FLAG) == "1"
            if not local and not resume:
                target = START_PATH
                # raw_query_string retains mobile client state and redirect encoding.
                if request.raw_path.partition("?")[2]:
                    target += "?" + request.raw_path.partition("?")[2]
                return redirect(target)
            response = await handler(request)
            response = await _authorize_html(handle, response)
            cookie(response, MODE_COOKIE, "local" if local else "oidc", 60)
            if local:
                cookie(response, TICKET_COOKIE, "", 0)
            return private_response(response)
        if request.path != "/auth/providers":
            return await handler(request)
        response = await handler(request)
        mode = request.cookies.get(MODE_COOKIE)
        if mode not in {"local", "oidc"} or response.status != 200:
            return response
        # The core endpoint is JSON, not a streamed/static response. Fail closed
        # on a changed response contract instead of modifying unrelated responses.
        if not isinstance(response, web.Response) or response.content_type != "application/json":
            return response
        data = json.loads(response.body)
        providers = data.get("providers")
        if not isinstance(providers, list):
            return response
        if mode == "local":
            providers = [p for p in providers if p.get("type") != PROVIDER_TYPE]
            providers.sort(key=lambda p: p.get("type") != "homeassistant")
        else:
            providers.sort(key=lambda p: p.get("type") != PROVIDER_TYPE)
            if any(p.get("type") == PROVIDER_TYPE for p in providers):
                # HA defaults this off for Tailscale's non-local addresses.
                # Native immediate-success flows use this value without ever
                # showing the checkbox, so explicitly scoped SSO must opt in.
                data["preselect_remember_me"] = True
        data["providers"] = providers
        # Preserve core headers (including CORS/security), but regenerate length.
        headers = {
            k: v
            for k, v in response.headers.items()
            if k.lower() not in {"content-length", "content-type", "content-encoding"}
        }
        result = web.json_response(data, headers=headers)
        cookie(result, MODE_COOKIE, "", 0)
        return private_response(result)

    return bridge


async def async_install(
    hass: Any,
    *,
    oidc: Any,
    sessions: Any,
    bindings: Mapping[tuple[str, str], str],
    callback_url: str,
    header_identity: Any = None,
) -> AdapterHandle:
    """Register once, during YAML setup, only on an exactly audited HA release."""
    from homeassistant.const import __version__

    from .provider import TsidpAuthProvider
    from .views import BridgeView, CallbackView, StartView

    if __version__ not in SUPPORTED_HA_VERSIONS:
        raise RuntimeError(f"tsidp adapter supports Home Assistant {SUPPORTED_HA_DESCRIPTION} only")
    app = hass.http.app
    if app.router.frozen:
        raise RuntimeError("tsidp cannot register views on a frozen HTTP router")
    frozen_app = app.frozen or app.middlewares.frozen
    target_routes = []
    if frozen_app:
        # Both audited HA releases deliberately disable router.freeze on start,
        # but aiohttp freezes the application/middleware list normally. Do not
        # unfreeze either object: wrap only the two already-existing GET routes.
        for path in (AUTHORIZE_PATH, "/auth/providers"):
            matches = [
                route
                for route in app.router.routes()
                if route.method == "GET" and route.get_info().get("path") == path
            ]
            if len(matches) != 1 or not hasattr(matches[0], "_handler"):
                raise RuntimeError(f"tsidp expected exactly one existing GET route for {path}")
            target_routes.append(matches[0])
    if hass.auth.get_auth_provider(PROVIDER_TYPE, None) is not None:
        raise RuntimeError("tsidp provider already registered; restart before reloading")
    if hass.auth.get_auth_provider("homeassistant", None) is None:
        raise RuntimeError("The homeassistant password provider must remain enabled")
    parsed = urlsplit(callback_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
        raise ValueError("callback_url must be an absolute HTTPS URL without query or fragment")
    if parsed.username or parsed.password or parsed.path != "/auth/tsidp/callback":
        raise ValueError("callback_url must use /auth/tsidp/callback and no userinfo")
    provider = TsidpAuthProvider(
        hass,
        hass.auth._store,
        sessions,
        bindings,
        f"{parsed.scheme}://{parsed.netloc}",
        header_identity=header_identity,
    )
    await provider.async_initialize()
    handle = AdapterHandle(hass, provider)
    # HA-private auth registration stays isolated here; route._handler is the
    # only additional aiohttp-private field used for already-running HA HTTP.
    middleware = make_middleware(handle)
    installed_middleware = False
    try:
        hass.auth._providers[(PROVIDER_TYPE, None)] = provider
        if frozen_app:
            for route in target_routes:
                original = route.handler

                def make_wrapper(handler):
                    async def wrapped(request):
                        return await middleware(request, handler)

                    return wrapped

                wrapper = make_wrapper(original)
                handle.route_handlers.append((route, original, wrapper))
                route._handler = wrapper
        else:
            app.middlewares.append(middleware)
            installed_middleware = True
        hass.http.register_view(StartView(handle, oidc, sessions))
        if header_identity is None:
            hass.http.register_view(CallbackView(handle, oidc, sessions, bindings))
        hass.http.register_view(BridgeView(handle))
    except Exception:
        handle.disable()
        if installed_middleware:
            app.middlewares.remove(middleware)
        raise
    return handle
