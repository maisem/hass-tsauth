# Compatibility and 2026.10.2 restoration (v0.2.1)

## Policy

Home Assistant versions identify completed audits, **not an enable/disable gate**.
An unaudited patch or monthly version logs a warning and runs the same runtime
preflight. There is no frontend-build or aiohttp-version allowlist.

Before changing providers/routes, the adapter checks actual auth registry,
required auth methods, application and (for a frozen app) exact GET route shapes.
Only five native security-sensitive callables are fingerprinted: finish-flow's
mapping/MFA path, native MFA validation, code-issuance response, one-use code store,
and authorization-code/PKCE exchange. Fingerprints use function ASTs, ignoring
comments, formatting and docstrings; unrelated module changes are not checked.
Changed security implementations or unavailable source require review. These
fingerprints are conservative checks, not a claim to prove arbitrary new HA safe.

The provider must explicitly support native MFA. Both reused and newly linked
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
`.venv-ha-202610` (2026.10.1), `.venv-ha-2026102` (2026.10.2).
The latter contains `home-assistant-frontend==20260930.4` and aiohttp 3.14.5.

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
