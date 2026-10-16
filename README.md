# hass-tsauth

**Log into Home Assistant with Tailscale. No OIDC server needed.**

Requires **HA 2026.9.3 or 2026.10.1**, [HACS](https://www.hacs.xyz/docs/use/), and
[Tailscale Serve](https://tailscale.com/kb/1312/serve) proxying your HTTPS tailnet
address to HA. Keep your existing HA password login enabled.

## 1. Install

1. **HACS → ⋮ → Custom repositories**.
2. Add `https://github.com/maisem/hass-tsauth`, category **Integration**.
3. Download **Tailscale Login**. Configure below before restarting.

## 2. Configure

Find your exact **Tailscale login name** in the Tailscale admin console
(often your email, not your display name or numeric user ID).
Find your **HA user ID** under **Developer Tools → States → person.… → user_id**.
If missing, link that person to your existing account under **Settings → People**.

Add to `/config/configuration.yaml`, replacing the examples:

```yaml
tsidp:
  auth_mode: headers
  base_url: https://YOUR-HA.example.ts.net
  trusted_proxies:
    - "127.0.0.1"
  users:
    "YOUR_EXACT_TAILSCALE_LOGIN": "YOUR_32_CHARACTER_HA_USER_ID"
```

**Trust only Serve's actual TCP source IP.** `127.0.0.1` applies when Serve
connects to `http://127.0.0.1:8123` in HA's host/network namespace. Container
setups may differ; verify the address. No subnets or wildcards. This is separate
from HA's `http.trusted_proxies` setting. Do not put another proxy that forwards
untrusted identity headers behind the same trusted IP.

## 3. Restart and sign in

Restart **Home Assistant**. Open your HA HTTPS address from a **personal,
untagged** Tailscale-connected phone/computer. Your existing **HA MFA still applies**.
The HA frontend and official iOS/Android apps are supported.

## Troubleshooting

- **Password page?** Tagged devices have no personal identity. Check your exact
  login mapping, Serve URL and proxy source IP. Missing/unmapped headers use passwords.
- **Need password login?** Append `&tsidp_local=1` to `/auth/authorize?...`.
- **Updates:** Update in HACS, then restart. Other HA versions are blocked.
- **Remove:** Delete the `tsidp:` block, restart, then optionally remove in HACS.

<details>
<summary>Upgrading from 0.1.x / legacy OIDC</summary>

For Serve, remove `issuer`, `client_id`, and `client_secret`; use the config above.
Replace each old OIDC subject key (`userid:…`) with the exact Tailscale login;
keep the same HA user ID. Existing credentials and refresh sessions are retained.
Legacy OIDC still works with its old config (or explicit `auth_mode: oidc`),
without `trusted_proxies`. Header mode does not contact the old IdP.

</details>

<details>
<summary>Security and manual installation</summary>

Serve strips incoming identity headers. Only an explicitly trusted transport peer
can supply `Tailscale-User-Login`; forwarded IPs and direct LAN claims are ignored.
Other software on that trusted host is inside the trust boundary. Restrict backend
exposure where practical. Mappings are exact; no email inference or user creation.
Native HA owns MFA, PKCE and tokens; arbitrary third-party clients get no silent SSO.

Without HACS, download `tsidp-VERSION.zip` from GitHub Releases (not `tsidp.zip`),
copy `custom_components/tsidp` into `/config/custom_components/`, configure and restart.

</details>

MIT licensed.
