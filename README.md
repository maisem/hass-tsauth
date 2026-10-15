# hass-tsauth

**Log into Home Assistant with Tailscale.**

## Before you start

- [ ] Home Assistant **2026.9.3**.
- [ ] A working [tsidp](https://github.com/tailscale/tsidp) server.
- [ ] Tailscale connected on your phone/computer and Home Assistant.
- [ ] An HTTPS address for Home Assistant.

## 1. Copy the files

1. On this GitHub page, click **Code → Download ZIP**.
2. Unzip it.
3. Copy the **`tsidp` folder inside `custom_components`** into Home Assistant's
   `/config/custom_components/` folder. Use Studio Code Server or a Samba share.

**Check:** this file should now exist:

```text
/config/custom_components/tsidp/manifest.json
```

## 2. Find your two user IDs

**Tailscale user ID**

On your own Tailscale-connected computer—not the HA server—run:

```sh
tailscale status --json
```

Copy the number in **`Self.UserID`**. Legacy tsidp uses `userid:` followed by
that number as your login subject. If your tsidp gives you a different `sub`,
use that exact value instead.

**Home Assistant user ID**

In HA, open **Developer Tools → States**, find your **`person.…`** entity,
and copy its **`user_id`** attribute. If it is missing, link that person to your
user under **Settings → People** first.

## 3. Paste the config

Add this to `/config/configuration.yaml`.
**Replace the two addresses and the two user IDs:**

```yaml
tsidp:
  issuer: https://YOUR-IDP.example.ts.net
  base_url: https://YOUR-HA.example.ts.net
  client_id: home-assistant-tsidp
  users:
    "userid:YOUR_TAILSCALE_USER_ID": "YOUR_HOME_ASSISTANT_USER_ID"
```

Use an existing HA account. Don't create a second account for this.
If another SSO integration is configured, disable its config first.

## 4. Restart and sign in

1. Restart **Home Assistant**, not just the browser.
2. Open your HA HTTPS address in a private browser window, with Tailscale on.
3. You should go through tsidp and land back in HA.

Your existing HA MFA still applies. The official iOS and Android apps are supported.

### Something went wrong?

- **Need your password?** Click **Use Home Assistant password** on the error page.
  Or append `&tsidp_local=1` to the `/auth/authorize?...` sign-in URL.
- **Can't reach tsidp?** Check that HA itself can resolve and open the IDP address.
- **Tagged-node error?** Sign in from your personal device, not a tagged server.
- **Want to undo it?** Remove the `tsidp:` config block and restart HA.

MIT licensed.
