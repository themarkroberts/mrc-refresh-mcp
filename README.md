# mrc-refresh-mcp

Remote MCP server that exposes `mrc-refresh` as a tool over HTTPS. Lets contractors run dev-site refreshes from Claude Desktop without ever holding an SSH key, an `op` session, or any credentials at all — they just hold a bearer token.

```
Contractor (Claude Desktop)
        │ HTTPS + Bearer <token>
        ▼
mcp.markroberts.io       ◄── this repo, deployed to the bastion
        │
        ▼
/usr/local/bin/mrc-refresh ──► live → dev
```

## Architecture

- **Caddy** terminates TLS at `mcp.markroberts.io` (auto cert via Let's Encrypt) and reverse-proxies to `127.0.0.1:8765`.
- **Uvicorn + Starlette** serves the MCP HTTP transport (`/`) plus an unauthenticated `/healthz`.
- **Bearer auth middleware** validates `Authorization: Bearer <token>` against `/etc/mrc-refresh-mcp/tokens.yml` on every request. Token revocation is instant (no restart).
- **`refresh_site` tool** invokes `mrc-refresh <site> [flags]` as the `mrc` user, captures stdout, parses `[N/4]` markers into MCP progress notifications, and returns the full log.
- **Audit log** at `/home/mrc/mrc-proxy/logs/contractor-access.log` (same file as the SSH-era audit log) tagged `via=mcp,contractor=<name>` so SSH-era and MCP-era entries are distinguishable.

## Install

On the bastion (`138.68.26.210`), as root:

```bash
curl -fsSL https://raw.githubusercontent.com/themarkroberts/mrc-refresh-mcp/main/install.sh -o /tmp/install.sh
sudo bash /tmp/install.sh
```

The install script is idempotent — re-run any time. It will:
1. Install python3, git, Caddy
2. Clone this repo to `/opt/mrc-refresh-mcp`
3. Set up a venv and install Python deps
4. Create `/etc/mrc-refresh-mcp/tokens.yml` (empty)
5. Install the systemd unit and start the service
6. Install the Caddy config and reload
7. Open ports 80, 443 in UFW (if active)

After install, confirm:
```bash
curl -s http://127.0.0.1:8765/healthz       # local
curl -s https://mcp.markroberts.io/healthz  # public (after DNS + cert)
```

## Issue a token

```bash
sudo /opt/mrc-refresh-mcp/scripts/issue-token.sh anton
```

Prints a token like `Hh3vL...PqZ9`. Copy it once and share via 1Password (one-time view, expiring link). Revoke by editing `/etc/mrc-refresh-mcp/tokens.yml` and removing the line.

## Contractor onboarding (Claude Desktop)

Contractor adds a remote MCP server in Claude Desktop:

- **Name:** `mrc-refresh`
- **URL:** `https://mcp.markroberts.io/mcp`  *(no trailing slash — Anthropic's connector validator does not follow redirects on the protocol endpoint, and FastMCP's canonical path is `/mcp` exactly)*
- **Auth header:** `Authorization: Bearer <their-token>`

After the connector is added, they can say things like "refresh canoefp" or "list available sites" and Claude will call the appropriate tool.

## GitHub Actions auto-deploy

`.github/workflows/deploy.yml` SSHes into the bastion on every push to `main` and updates the service. To wire it up:

1. **Create a deploy user on the bastion:**
   ```bash
   sudo useradd -m -s /bin/bash deploy
   sudo mkdir -p /home/deploy/.ssh
   ssh-keygen -t ed25519 -f /tmp/deploy_key -N "" -C "github-actions deploy"
   sudo cp /tmp/deploy_key.pub /home/deploy/.ssh/authorized_keys
   sudo chown -R deploy:deploy /home/deploy/.ssh
   sudo chmod 700 /home/deploy/.ssh
   sudo chmod 600 /home/deploy/.ssh/authorized_keys
   ```

2. **Grant the deploy user write access to the app dir and a scoped sudo:**
   ```bash
   sudo usermod -aG mrc deploy
   sudo chmod -R g+w /opt/mrc-refresh-mcp
   echo "deploy ALL=(root) NOPASSWD: /bin/systemctl restart mrc-refresh-mcp, /bin/systemctl is-active --quiet mrc-refresh-mcp" \
     | sudo tee /etc/sudoers.d/deploy-mrc-refresh-mcp
   sudo chmod 0440 /etc/sudoers.d/deploy-mrc-refresh-mcp
   ```

3. **Add GitHub repo secrets** (`Settings → Secrets and variables → Actions`):
   - `BASTION_HOST` = `138.68.26.210`
   - `DEPLOY_SSH_KEY` = contents of `/tmp/deploy_key` (the private key)

4. **Cleanup:** `rm /tmp/deploy_key /tmp/deploy_key.pub` on whatever machine you generated the key on.

After that, every `git push origin main` triggers the workflow, which pulls, reinstalls deps, restarts the service, and verifies it's healthy.

## Operations

| Task | How |
|---|---|
| Tail service logs | `journalctl -u mrc-refresh-mcp -f` |
| Tail TLS / proxy logs | `journalctl -u caddy -f` |
| Tail audit log | `tail -f /home/mrc/mrc-proxy/logs/contractor-access.log` |
| Issue token | `sudo /opt/mrc-refresh-mcp/scripts/issue-token.sh <name>` |
| Revoke token | edit `/etc/mrc-refresh-mcp/tokens.yml`, delete the line |
| Restart service | `sudo systemctl restart mrc-refresh-mcp` |
| Manual deploy (no CI) | `cd /opt/mrc-refresh-mcp && sudo -u mrc git pull && sudo -u mrc ./venv/bin/pip install -r requirements.txt && sudo systemctl restart mrc-refresh-mcp` |
| Renew TLS cert | automatic; manual force: `sudo systemctl reload caddy` |

## Threat model

- **Bearer tokens are the only contractor credential.** Each is mapped to a single contractor name in `tokens.yml`. If a token leaks, the blast radius is "an attacker can run `mrc-refresh <site>` against any of the six allowed sites." That overwrites the dev DB and dev wp-content. It does NOT grant shell access, does NOT touch live, does NOT expose any secret.
- **Tokens never traverse the contractor's machine in plaintext at rest** if delivered via 1Password share link (one-time view).
- **Audit log captures every invocation** with timestamp, contractor name, exit code, and full command. Same file as the SSH-era log.
- **Token rotation:** edit `tokens.yml`, change the line. Effective immediately, no restart.
- **Server compromise** is the same risk as today — the bastion already holds the live SSH keys. Adding the MCP server doesn't change that posture.

## What this replaces

Previously, contractors needed:
- 1Password CLI installed and signed in
- An MRC service-account token OR an interactive `op` session
- A per-contractor SSH key in 1Password
- A bastion-restricted SSH config

…all of which had to work inside Claude Desktop's Cowork sandbox, which is a Linux container isolated from the host. This was painful to provision and brittle.

Now contractors need: one bearer token. That's it.
