"""Tailscale authentication with explicit mappings and password fallback."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import voluptuous as vol

from .compatibility import AUDITED_HA_VERSIONS
from .configuration import DOMAIN, Settings, validate_mapping

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.typing import ConfigType

_LOGGER = logging.getLogger(__name__)
COMPATIBILITY_ISSUE = "runtime_compatibility"
CONFIG_SCHEMA = vol.Schema({vol.Optional(DOMAIN): validate_mapping}, extra=vol.ALLOW_EXTRA)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Remain loaded with a visible repair if SSO cannot safely be installed."""
    if DOMAIN not in config:
        return True

    from homeassistant.const import __version__  # noqa: PLC0415
    from homeassistant.helpers import issue_registry as ir  # noqa: PLC0415

    # Dates identify completed audits, not whether a runtime is safe to use.
    if __version__ not in AUDITED_HA_VERSIONS:
        _LOGGER.warning(
            "Home Assistant %s has not been audited with tsidp; checking runtime contracts",
            __version__,
        )
    if DOMAIN in hass.data:
        _LOGGER.warning("tsidp is already loaded; refusing a second provider")
        return True

    try:
        from homeassistant.helpers.importlib import async_import_module  # noqa: PLC0415

        # Import/construction incompatibilities must also produce a loaded,
        # degraded integration rather than silently disappearing from HA.
        adapter = await async_import_module(hass, f"{__package__}.ha_adapter")
        protocol = await async_import_module(hass, f"{__package__}.oidc")
        state = await async_import_module(hass, f"{__package__}.session")
        settings = Settings.from_mapping(config[DOMAIN])
        for user_id in settings.users.values():
            user = await hass.auth.async_get_user(user_id)
            if user is None or not user.is_active or user.system_generated:
                raise ValueError("Mapping refers to a missing, inactive or system HA account")

        oidc = None
        header_identity = None
        if settings.auth_mode == "headers":
            from .headers import HeaderIdentity  # noqa: PLC0415

            header_identity = HeaderIdentity(settings.trusted_proxies)
        else:
            oidc = protocol.OIDCClient(
                protocol.OIDCConfig(
                    issuer=settings.issuer,
                    client_id=settings.client_id,
                    callback_url=settings.callback_url,
                    client_secret=settings.client_secret,
                )
            )
        sessions = state.SessionManager()
        handle = await adapter.async_install(
            hass,
            oidc=oidc,
            sessions=sessions,
            bindings=settings.bindings,
            callback_url=settings.callback_url,
            header_identity=header_identity,
        )
    except (RuntimeError, ValueError, ImportError, AttributeError, TypeError) as err:
        _LOGGER.exception("Unable to install tsidp SSO; existing password login remains enabled")
        ir.async_create_issue(
            hass,
            DOMAIN,
            COMPATIBILITY_ISSUE,
            is_fixable=False,
            is_persistent=True,
            severity=ir.IssueSeverity.ERROR,
            translation_key="runtime_compatibility",
            translation_placeholders={"reason": str(err)},
        )
        hass.data[DOMAIN] = {"compatibility_error": str(err)}
        return True

    hass.data[DOMAIN] = handle
    ir.async_delete_issue(hass, DOMAIN, COMPATIBILITY_ISSUE)
    _LOGGER.info("Tailscale authentication configured with explicit existing-account bindings")
    return True
