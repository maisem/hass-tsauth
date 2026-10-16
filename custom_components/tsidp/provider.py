"""Native HA login provider; identity proof arrives in a one-use browser cookie."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

from homeassistant.auth import InvalidAuthError
from homeassistant.auth.providers import AuthProvider, LoginFlow
from homeassistant.helpers.http import current_request

from .clients import is_trusted_client
from .ha_adapter import BROWSER_COOKIE, PROVIDER_TYPE, TICKET_COOKIE
from .session import SessionError, validate_authorize_path


class TsidpAuthProvider(AuthProvider):
    """Bind only explicit (issuer, sub) pairs to existing HA account UUIDs."""

    DEFAULT_TITLE = "Tailscale"

    def __init__(
        self,
        hass: Any,
        store: Any,
        sessions: Any,
        bindings: Mapping[tuple[str, str], str],
        origin: str,
    ) -> None:
        super().__init__(hass, store, {"type": PROVIDER_TYPE, "name": self.DEFAULT_TITLE})
        self.sessions = sessions
        self.bindings = dict(bindings)
        self.origin = origin
        self._credential_lock = asyncio.Lock()

    async def async_login_flow(self, context=None):
        return TsidpLoginFlow(self)

    async def async_get_or_create_credentials(self, flow_result: Mapping[str, str]):
        issuer, subject = flow_result["issuer"], flow_result["subject"]
        user_id = self.bindings.get((issuer, subject))
        if not user_id or user_id != flow_result.get("ha_user_id"):
            raise InvalidAuthError("Identity is not explicitly bound")
        user = await self.hass.auth.async_get_user(user_id)
        if user is None or not user.is_active or user.system_generated:
            raise InvalidAuthError("Bound account is unavailable")
        async with self._credential_lock:
            for credential in await self.async_credentials():
                if credential.data == {"issuer": issuer, "subject": subject}:
                    linked = await self.hass.auth.async_get_user_by_credentials(credential)
                    if linked is None or linked.id != user_id:
                        raise InvalidAuthError("Existing credential has a different binding")
                    return credential
            credential = self.async_create_credentials({"issuer": issuer, "subject": subject})
            await self.hass.auth.async_link_user(user, credential)
            return credential

    async def async_user_meta_for_credentials(self, credentials):
        # Every credential must already be linked. Never provision a user or
        # infer a username from email/name claims if the configured user vanishes.
        raise InvalidAuthError("Automatic account provisioning is disabled")


class TsidpLoginFlow(LoginFlow):
    """Finish through HA's ordinary credential and MFA processing, not token minting."""

    async def async_step_init(self, user_input=None):
        request = current_request.get()
        if (
            request is None
            or request.method != "POST"
            or request.path != "/auth/login_flow"
            or request.headers.get("Origin") != self._auth_provider.origin
        ):
            return self.async_abort(reason="invalid_auth")
        try:
            ticket = self._auth_provider.sessions.consume_ticket(
                request.cookies.get(TICKET_COOKIE, ""),
                request.cookies.get(BROWSER_COOKIE, ""),
            )
        except SessionError:
            # Native provider selection/start-over can arrive without a fresh
            # one-use handoff. Only the authorize-page bridge restarts SSO;
            # malformed origin/path/client checks still fail closed below.
            return self.async_abort(reason="restart_sso")
        try:
            path = validate_authorize_path(ticket.return_path)
            expected = parse_qs(urlsplit(path).query, keep_blank_values=True)
            submitted = await request.json()
            if (
                not isinstance(submitted, dict)
                or submitted.get("client_id") != expected["client_id"][0]
                or submitted.get("redirect_uri") != expected["redirect_uri"][0]
                or self.context.get("redirect_uri") != expected["redirect_uri"][0]
                or not is_trusted_client(
                    self._auth_provider.origin,
                    submitted.get("client_id"),
                    submitted.get("redirect_uri"),
                )
            ):
                return self.async_abort(reason="invalid_auth")
        except (ValueError, SessionError):
            return self.async_abort(reason="invalid_auth")
        identity = ticket.identity
        if (
            self._auth_provider.bindings.get((identity.issuer, identity.subject))
            != ticket.ha_user_id
        ):
            return self.async_abort(reason="invalid_auth")
        user = await self._auth_manager.async_get_user(ticket.ha_user_id)
        if user is None or not user.is_active or user.system_generated:
            return self.async_abort(reason="invalid_auth")
        # Returning a mapping rather than a Credentials object is important:
        # AuthManagerFlowManager.async_finish_flow then runs HA's existing MFA.
        return await self.async_finish(
            {
                "issuer": identity.issuer,
                "subject": identity.subject,
                "ha_user_id": ticket.ha_user_id,
            }
        )
