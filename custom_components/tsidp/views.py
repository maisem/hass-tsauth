"""Integration-owned redirects and restart asset; no HA token/code implementation."""

from __future__ import annotations

from collections.abc import Mapping
from html import escape
from pathlib import Path
from typing import Any

from aiohttp import web
from homeassistant.components.auth import indieauth
from homeassistant.components.http import HomeAssistantView

from .clients import is_trusted_client
from .ha_adapter import (
    AUTHORIZE_PATH,
    BRIDGE_PATH,
    BROWSER_COOKIE,
    LOCAL_FLAG,
    RESUME_FLAG,
    START_PATH,
    TICKET_COOKIE,
    cookie,
    private_response,
    redirect,
)
from .oidc import OIDCError
from .session import SessionError, new_browser_secret, validate_authorize_path


def _failure(status: int = 400, return_path: str | None = None) -> web.Response:
    link = ""
    if return_path is not None:
        path = validate_authorize_path(return_path)
        separator = "&" if "?" in path else "?"
        link = (
            '<p><a href="'
            + escape(f"{path}{separator}{LOCAL_FLAG}=1", quote=True)
            + '">Use Home Assistant password</a></p>'
        )
    response = web.Response(
        status=status,
        content_type="text/html",
        text=(
            "<!doctype html><meta name=viewport content='width=device-width'>"
            "<title>Home Assistant sign-in</title>"
            "<h1>Sign-in could not be completed</h1>"
            "<p>Start again or use your Home Assistant password.</p>" + link
        ),
    )
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return private_response(response)


def _one(query, name: str, *, required: bool = True) -> str:
    values = query.getall(name, [])
    if len(values) > 1 or (required and (not values or not values[0])):
        raise ValueError("Invalid authorization parameters")
    return values[0] if values else ""


class BridgeView(HomeAssistantView):
    """Public same-origin script loaded only by the native authorize HTML."""

    url = BRIDGE_PATH
    name = "tsidp:bridge"
    requires_auth = False

    def __init__(self, handle: Any) -> None:
        self.handle = handle

    async def get(self, request: web.Request) -> web.StreamResponse:
        if not self.handle.enabled:
            return private_response(web.Response(status=404))
        body = await self.handle.hass.async_add_executor_job(
            Path(__file__).with_name("frontend.js").read_bytes
        )
        response = web.Response(body=body, content_type="application/javascript")
        response.headers["X-Content-Type-Options"] = "nosniff"
        return private_response(response)


class StartView(HomeAssistantView):
    url = START_PATH
    name = "tsidp:start"
    requires_auth = False

    def __init__(self, handle: Any, oidc: Any, sessions: Any) -> None:
        self.handle, self.oidc, self.sessions = handle, oidc, sessions

    async def get(self, request: web.Request) -> web.StreamResponse:
        if not self.handle.enabled:
            return _failure(503)
        return_path = None
        try:
            client_id = _one(request.query, "client_id")
            redirect_uri = _one(request.query, "redirect_uri")
            _one(request.query, "state", required=False)
            if LOCAL_FLAG in request.query or RESUME_FLAG in request.query:
                raise ValueError("Reserved query flag")
            response_type = _one(request.query, "response_type", required=False)
            if response_type and response_type != "code":
                raise ValueError("Unsupported response type")
            return_path = validate_authorize_path(
                AUTHORIZE_PATH + "?" + request.raw_path.partition("?")[2]
            )
            if not is_trusted_client(self.handle.provider.origin, client_id, redirect_uri):
                return _failure(403, return_path)
            if not indieauth.verify_client_id(client_id):
                raise ValueError("Invalid client")
            if not await indieauth.verify_redirect_uri(self.handle.hass, client_id, redirect_uri):
                raise ValueError("Invalid redirect")
            browser = request.cookies.get(BROWSER_COOKIE) or new_browser_secret()
            authorization = await self.oidc.begin()
            self.sessions.add(authorization, browser, return_path)
        except (ValueError, SessionError, OIDCError):
            return _failure(return_path=return_path)
        response = redirect(authorization.authorization_url)
        cookie(response, BROWSER_COOKIE, browser, 300)
        cookie(response, TICKET_COOKIE, "", 0)
        return private_response(response)


class CallbackView(HomeAssistantView):
    url = "/auth/tsidp/callback"
    name = "tsidp:callback"
    requires_auth = False

    def __init__(
        self, handle: Any, oidc: Any, sessions: Any, bindings: Mapping[tuple[str, str], str]
    ) -> None:
        self.handle, self.oidc, self.sessions = handle, oidc, sessions
        self.bindings = dict(bindings)

    async def get(self, request: web.Request) -> web.StreamResponse:
        if not self.handle.enabled:
            return _failure(503)
        return_path = None
        try:
            state = _one(request.query, "state")
            browser = request.cookies.get(BROWSER_COOKIE, "")
            transaction = self.sessions.consume_state(state, browser)
            return_path = transaction.return_path
            # Consume denial/error state too, before any remote exchange.
            if "error" in request.query:
                return _failure(return_path=return_path)
            code = _one(request.query, "code")
            identity = await self.oidc.complete(transaction.authorization, code)
            user_id = self.bindings.get((identity.issuer, identity.subject))
            if user_id is None:
                return _failure(403, return_path)
            user = await self.handle.hass.auth.async_get_user(user_id)
            if user is None or not user.is_active or user.system_generated:
                return _failure(403, return_path)
            ticket = self.sessions.issue_ticket(identity, browser, user_id, return_path=return_path)
            path = validate_authorize_path(transaction.return_path)
        except (ValueError, SessionError, OIDCError):
            return _failure(return_path=return_path)
        separator = "&" if "?" in path else "?"
        response = redirect(f"{path}{separator}{RESUME_FLAG}=1")
        cookie(response, TICKET_COOKIE, ticket, 60)
        return private_response(response)
