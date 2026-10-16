"""Focused Tailscale identity authentication for Home Assistant.

No OIDC credentials are linked by email/username, and no new HA users are
provisioned. Protocol/state modules remain independently testable.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import voluptuous as vol

from .compatibility import SUPPORTED_HA_DESCRIPTION, SUPPORTED_HA_VERSIONS
from .configuration import DOMAIN, Settings, validate_mapping

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.typing import ConfigType

_LOGGER = logging.getLogger(__name__)
CONFIG_SCHEMA = vol.Schema({vol.Optional(DOMAIN): validate_mapping}, extra=vol.ALLOW_EXTRA)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register one explicitly configured provider without changing local login."""
    if DOMAIN not in config:
        return True

    # These are the only exact HA releases whose private APIs we have audited.
    # Refuse untested versions before registering middleware or auth providers.
    from homeassistant.const import __version__  # noqa: PLC0415

    if __version__ not in SUPPORTED_HA_VERSIONS:
        _LOGGER.error(
            "tsidp supports Home Assistant %s only; local login unchanged",
            SUPPORTED_HA_DESCRIPTION,
        )
        return False

    from homeassistant.helpers.importlib import async_import_module  # noqa: PLC0415

    adapter = await async_import_module(hass, f"{__package__}.ha_adapter")
    protocol = await async_import_module(hass, f"{__package__}.oidc")
    state = await async_import_module(hass, f"{__package__}.session")

    if DOMAIN in hass.data:
        _LOGGER.error("tsidp is already installed; refusing a second provider")
        return False

    settings = Settings.from_mapping(config[DOMAIN])
    # Re-check existing-account bindings BEFORE installing a publicly reachable callback.
    for user_id in settings.users.values():
        user = await hass.auth.async_get_user(user_id)
        if user is None or not user.is_active or user.system_generated:
            _LOGGER.error("tsidp user mapping refers to a missing, inactive or system HA account")
            return False

    oidc = protocol.OIDCClient(
        protocol.OIDCConfig(
            issuer=settings.issuer,
            client_id=settings.client_id,
            callback_url=settings.callback_url,
            client_secret=settings.client_secret,
        )
    )
    sessions = state.SessionManager()
    try:
        handle = await adapter.async_install(
            hass,
            oidc=oidc,
            sessions=sessions,
            bindings=settings.bindings,
            callback_url=settings.callback_url,
        )
    except (RuntimeError, ValueError):
        _LOGGER.exception("Unable to install tsidp; keep the local password provider enabled")
        return False

    hass.data[DOMAIN] = handle
    _LOGGER.info("Tailscale authentication configured with explicit existing-account bindings")
    return True
