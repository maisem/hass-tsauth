# Compatibility (v0.2.3, audited through Core 2026.11.1)

## Policy

Home Assistant versions identify completed audits, **not an enable/disable gate**.
An unaudited patch or monthly version logs a warning and runs the same runtime
preflight. There is no frontend-build or aiohttp-version allowlist.

Before changing providers/routes, the adapter checks actual auth registry,
required auth methods, application and (for a frozen app) exact GET route shapes.
Only native security-sensitive callables are fingerprinted: the MFA enforcement
point and MFA validation (one complete reviewed layout must match, see 2026.11.1
below), code-issuance response, one-use code store, and authorization-code/PKCE
exchange. Fingerprints use function ASTs, ignoring
comments, formatting and docstrings; unrelated module changes are not checked.
Changed security implementations or unavailable source require review. These
fingerprints are conservative checks, not a claim to prove arbitrary new HA safe.

The login flow must finish through native MFA: on Core ≤ 2026.10 the provider
must report `support_mfa`; on 2026.11 the flow must inherit `MfaLoginFlow.async_finish`
unchanged, exactly as the native password flow does. Both reused and newly linked
credentials must be non-new and linked to the intended active, non-system account
before being returned to native finish-flow. Proxy trust, explicit account mapping,
one-use browser-bound tickets/state, native client/redirect binding and S256 PKCE
are unchanged. No accounts or tokens are provisioned by a compatibility fallback.

On a compatibility/import/construction failure the component **stays loaded**, no
SSO provider is left registered, and a persistent error appears in **Settings →
System → Repairs**. Existing password login and MFA remain available. A successful
setup clears that repair. Restart after installing a reviewed compatible release.
No workaround should remove MFA, broaden trusted proxies, or edit HA's auth store.

A future frontend change could still break automatic provider selection/restart
(availability). Frontend build numbers alone do not disable SSO. The backend proof,
request, account and MFA checks remain authoritative; use password login if needed.

## Official upstream audit

### Core 2026.11.1 (frontend 20261028.5, aiohttp 3.14.5)

Compared with 2026.10.2/2026.10.4. All five fingerprinted functions changed:

- **MFA moved.** `AuthManagerFlowManager.async_finish_flow` no longer challenges;
  `AuthProvider.support_mfa` is gone. The challenge is now
  `MfaLoginFlow.async_finish` (`homeassistant/auth/providers/__init__.py`), used by
  the password, command-line and example providers. A plain `LoginFlow` (as
  trusted networks uses) is **not** challenged. v0.2.2 and earlier derive from
  `LoginFlow` and would skip MFA on 2026.11 had the guard not refused to install.
  v0.2.3 derives from `MfaLoginFlow` when Core has it, and the adapter refuses
  an overridden `async_finish`. `async_step_mfa` moved with it; it differs only
  in calling the base `async_finish` after a valid code.
- `_async_flow_result_to_response`: redirect check also receives the request
  scheme/host. `_create_auth_code_store`: expired codes are purged on store.
  `_async_handle_auth_code`: client check receives scheme/host, codes of removed
  credentials are refused, duplicate new credentials are refused. All stricter;
  this integration only ever returns linked, non-new credentials.
- `indieauth.verify_client_id`/`verify_redirect_uri` require `request_scheme` and
  `request_netloc`; `/auth/tsidp/start` passes them as Core's own views do.
- `async_create_flow` asks `async_can_start_login` (inherited, always true) and
  raises `UnknownHandler`; nothing here catches the former `KeyError`.
- Unchanged: `/auth/authorize` static file route, `/auth/providers` JSON shape,
  disabled router freeze, `_providers`/`_store`. Frontend auth sources only gain
  `response_type` forwarding; picker and event helper are identical.

### Core 2026.10.2

Compared the official release tags and installed release wheels:

- [Core 2026.10.1…2026.10.2](https://github.com/home-assistant/core/compare/2026.10.1...2026.10.2):
  `AuthManager.async_remove_user` now revokes refresh tokens, closing active
  connections. Config password creation gains owner authorization, duplicate
  credential protection and a lock. These do not change this integration's native
  login handoff, mapping, MFA or PKCE functions; their ASTs are identical.
- Core frontend dependency changes **20260930.3 → 20260930.4**.
  [Frontend comparison](https://github.com/home-assistant/frontend/compare/20260930.3...20260930.4)
  has no authorize/auth/provider-picker source changes (changes concern maps,
  Matter, automation conditions, tables and related UI/tests). Rebuilt bundles
  differ; contract tests execute the installed bundle's actual native functions.
- Core aiohttp changes **3.14.4 → 3.14.5**.
  [aiohttp comparison](https://github.com/aio-libs/aiohttp/compare/v3.14.4...v3.14.5)
  changes WebSocket RSV1 control-frame interoperability and dependency bounds.
  `web_app.py`, `web_fileresponse.py` and `web_urldispatcher.py` are unchanged;
  the adapter's `FileResponse._path` and exact-route `_handler` contracts persist.

## Bounded local validation (no live HA)

The Python 3.14 environments are separate: `.venv-ha` (2026.9.3),
`.venv-ha-202610` (2026.10.1), `.venv-ha-2026102` (2026.10.2) and
`.venv-ha-2026111` (2026.11.1, `home-assistant-frontend==20261028.5`,
`httpx2==2.14.0`). The 2026.10.2 one was created as follows; substitute versions.

```sh
uv venv --python .venv-ha-202610/bin/python .venv-ha-2026102
uv pip install --python .venv-ha-2026102/bin/python \
  'homeassistant==2026.10.2' 'home-assistant-frontend==20260930.4' \
  'pytest>=8.3,<10' 'pytest-asyncio>=0.24,<2' \
  'Authlib==1.9.1' 'httpx2==2.13.0' 'joserfc==1.7.5'
timeout 90 .venv-ha-2026102/bin/pytest -q
TSIDP_HA_FRONTEND="$PWD/.venv-ha-2026102/lib/python3.14/site-packages/hass_frontend" \
  timeout 30 node --test tests/*.test.cjs
.venv/bin/ruff check .
.venv/bin/ruff format --check .
python3 scripts/build_release.py
```

Repeat pytest in the other isolated environments for regression coverage. These
are actual AuthManager/store/login-flow/MFA/token tests and installed-frontend
function contract tests, **not a full browser or Companion-device E2E claim**.
There are also future-version acceptance, real Repairs creation/clearing, changed
contract rollback, unsafe credential-link and native-MFA-support regressions.
