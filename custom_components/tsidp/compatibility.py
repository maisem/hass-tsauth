"""Exact Core releases audited against their bundled auth frontend.

2026.9.3: home-assistant-frontend 20260826.7
2026.10.1: home-assistant-frontend 20260930.3 (optional native S256 PKCE)
"""

SUPPORTED_HA_VERSIONS = ("2026.9.3", "2026.10.1")
SUPPORTED_HA_DESCRIPTION = " or ".join(SUPPORTED_HA_VERSIONS)
