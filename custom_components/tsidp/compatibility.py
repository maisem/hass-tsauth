"""Version labels warn; narrow native security contracts determine SSO safety."""

from __future__ import annotations

import ast
import hashlib
import inspect
import textwrap
from importlib import import_module

AUDITED_HA_VERSIONS = ("2026.9.3", "2026.10.1", "2026.10.2", "2026.11.1")
# For tests/tools enumerating actually audited releases, not an installation gate.
SUPPORTED_HA_VERSIONS = AUDITED_HA_VERSIONS

# Only native security handoff/MFA/code/PKCE functions are fingerprinted. Changes
# elsewhere in Core, frontend or aiohttp never fail this check. ASTs ignore source
# formatting, comments and docstrings. A changed security path requires review.
SECURITY_CONTRACTS = {
    "homeassistant.components.auth.login_flow:LoginFlowBaseView._async_flow_result_to_response": (
        "b418ec59fc22d4c834512f26b6249ccd6d1f1fa246b32715924b84ad0383db84",
        "2ad441104425714b5867a59c86ab8065469ae369cd1d2a2708794d3d2b9921c0",
        "f553e88ece90025d102a0e27b5d7979a24228ce664b1a15350da00c95ef3cf32",  # 2026.11.1
    ),
    "homeassistant.components.auth:_create_auth_code_store": (
        "76b190377dbd0f45a80d89aa57d5cadef1abe3e83d823200552a6d21e9f26243",
        "78f8917d7e3090341ba245609710315bad2943de4b723bb5e1b0baf1fc57d052",
        "9df0c31e97733470efe071ca5a2507a0234f560fef77598e332e4fa66c847b62",  # 2026.11.1
    ),
    "homeassistant.components.auth:TokenView._async_handle_auth_code": (
        "673b18d8c5d163375838341b9896185de52823bd49f6f3c104760bf422a244a4",
        "48490b3775ffdbcb804257ccda37e74379519a20e90b54b82f7cab4b0d18454d",
        "0757a5ac92439a5ddd434f65fe95ae8561162cf084839efa64d2b7a62b44e391",  # 2026.11.1
    ),
}

# Where native MFA is enforced moved in Core 2026.11. One reviewed layout must
# match completely; hashes from different layouts are never mixed. None means
# the name must be absent. The provider's login flow follows the same layout.
MFA_LAYOUTS = (
    {  # Core <= 2026.10: finish-flow challenges any provider that supports MFA.
        "homeassistant.auth:AuthManagerFlowManager.async_finish_flow": (
            "a4f72e1a9d4d46363116de47f0c472bd2ad02dab1dfb0fc1041fc034479c06bd"
        ),
        "homeassistant.auth.providers:LoginFlow.async_step_mfa": (
            "af93afb362b4729802f72351b8c72002e170f6302c90e686e9ec9b504bde9cfe"
        ),
        "homeassistant.auth.providers:MfaLoginFlow": None,
    },
    {  # Core 2026.11: only flows derived from MfaLoginFlow are challenged.
        "homeassistant.auth:AuthManagerFlowManager.async_finish_flow": (
            "e99cf8abd6b350d7852f3e5911de66234c73455730e4deb9b3a2cb1e611f3015"
        ),
        "homeassistant.auth.providers:MfaLoginFlow.async_finish": (
            "1804ec0dda3c639541e6b8a67c86c158da5cbe1ea8d3bfb46708f8c579720f23"
        ),
        "homeassistant.auth.providers:MfaLoginFlow.async_step_mfa": (
            "7073eabeb05f1fe86038052e207d97b241baf5e4eb1286c2433f2804babdaeed"
        ),
        "homeassistant.auth.providers:LoginFlow.async_step_mfa": None,
    },
)


def security_fingerprint(function) -> str:
    """Hash one security-critical callable's AST, not its containing module."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(inspect.unwrap(function))))
    body = tree.body[0].body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body.pop(0)
    return hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()


def _resolve(name: str):
    """Return the named native object, or None if Core does not define it."""
    module, qualified = name.split(":")
    target = import_module(module)
    for attribute in qualified.split("."):
        target = getattr(target, attribute, None)
        if target is None:
            return None
    return target


def _matches(name: str, known_hashes: tuple[str, ...] | None) -> bool:
    target = _resolve(name)
    if known_hashes is None or target is None:
        return known_hashes is None and target is None
    return callable(target) and security_fingerprint(target) in known_hashes


def check_runtime_contracts() -> None:
    """Check native security semantics in an executor before auth/HTTP mutation.

    No Core, frontend, or dependency version allowlist. Unknown versions with
    unchanged safety contracts work; real security-path changes need review.
    The adapter separately checks actual registry/application/route shapes.
    """
    try:
        for name, known_hashes in SECURITY_CONTRACTS.items():
            if _resolve(name) is None:
                raise AttributeError(name)
            if not _matches(name, known_hashes):
                raise RuntimeError(f"Changed native security contract: {name}")
        if not any(
            all(_matches(name, known and (known,)) for name, known in layout.items())
            for layout in MFA_LAYOUTS
        ):
            raise RuntimeError("Changed native security contract: MFA enforcement")
    except (ImportError, AttributeError, OSError, TypeError, SyntaxError) as err:
        raise RuntimeError("Required native security callable/source is unavailable") from err
