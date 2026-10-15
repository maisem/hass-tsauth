"""Clients permitted to receive HA codes without a separate consent interaction.

HA's IndieAuth validation alone permits arbitrary third-party apps. Silently
signing in such a client could disclose an HA authorization code to a malicious
website, so seamless login is deliberately restricted to these exact pairs.
"""


def is_trusted_client(origin: str, client_id: str, redirect_uri: str) -> bool:
    """Recognize HA's own frontend and the official Android/iOS Companion clients."""
    pairs = {
        (origin + "/", origin + "/?auth_callback=1"),
        ("https://home-assistant.io/android", "homeassistant://auth-callback"),
        ("https://home-assistant.io/iOS", "homeassistant://auth-callback"),
    }
    return (client_id, redirect_uri) in pairs
