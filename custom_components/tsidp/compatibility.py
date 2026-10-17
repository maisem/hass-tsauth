"""Version labels warn; narrow native security contracts determine SSO safety."""

from __future__ import annotations

import ast
import hashlib
import inspect
import textwrap
from importlib import import_module

AUDITED_HA_VERSIONS = ("2026.9.3", "2026.10.1", "2026.10.2")
# For tests/tools enumerating actually audited releases, not an installation gate.
SUPPORTED_HA_VERSIONS = AUDITED_HA_VERSIONS

# Only native security handoff/MFA/code/PKCE functions are fingerprinted. Changes
# elsewhere in Core, frontend or aiohttp never fail this check. ASTs ignore source
# formatting, comments and docstrings. A changed security path requires review.
SECURITY_CONTRACTS = {
    "homeassistant.auth:AuthManagerFlowManager.async_finish_flow": (
        "a4f72e1a9d4d46363116de47f0c472bd2ad02dab1dfb0fc1041fc034479c06bd",
    ),
    "homeassistant.auth.providers:LoginFlow.async_step_mfa": (
        "af93afb362b4729802f72351b8c72002e170f6302c90e686e9ec9b504bde9cfe",
    ),
    "homeassistant.components.auth.login_flow:LoginFlowBaseView._async_flow_result_to_response": (
        "b418ec59fc22d4c834512f26b6249ccd6d1f1fa246b32715924b84ad0383db84",
        "2ad441104425714b5867a59c86ab8065469ae369cd1d2a2708794d3d2b9921c0",
    ),
    "homeassistant.components.auth:_create_auth_code_store": (
        "76b190377dbd0f45a80d89aa57d5cadef1abe3e83d823200552a6d21e9f26243",
        "78f8917d7e3090341ba245609710315bad2943de4b723bb5e1b0baf1fc57d052",
    ),
    "homeassistant.components.auth:TokenView._async_handle_auth_code": (
        "673b18d8c5d163375838341b9896185de52823bd49f6f3c104760bf422a244a4",
        "48490b3775ffdbcb804257ccda37e74379519a20e90b54b82f7cab4b0d18454d",
    ),
}


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


def check_runtime_contracts() -> None:
    """Check native security semantics in an executor before auth/HTTP mutation.

    No Core, frontend, or dependency version allowlist. Unknown versions with
    unchanged safety contracts work; real security-path changes need review.
    The adapter separately checks actual registry/application/route shapes.
    """
    try:
        for name, known_hashes in SECURITY_CONTRACTS.items():
            module, qualified = name.split(":")
            function = import_module(module)
            for attribute in qualified.split("."):
                function = getattr(function, attribute)
            if not callable(function) or security_fingerprint(function) not in known_hashes:
                raise RuntimeError(f"Changed native security contract: {name}")
    except (ImportError, AttributeError, OSError, TypeError, SyntaxError) as err:
        raise RuntimeError("Required native security callable/source is unavailable") from err
