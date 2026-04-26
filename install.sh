#!/usr/bin/env bash
# MRC Refresh MCP — bastion install script.
# Run as root on the bastion (138.68.26.210). Idempotent: safe to re-run.
#
# Assumes:
# - Debian/Ubuntu host with apt
# - The `mrc` user already exists (it does — used by mrc-refresh today)
# - /usr/local/bin/mrc-refresh is already installed
# - DNS A record for $DOMAIN already points at this server

set -euo pipefail

DOMAIN="${DOMAIN:-mcp.markroberts.io}"
APP_DIR="/opt/mrc-refresh-mcp"
CONFIG_DIR="/etc/mrc-refresh-mcp"
TOKENS_FILE="$CONFIG_DIR/tokens.yml"
SERVICE_NAME="mrc-refresh-mcp"
REPO_URL="${REPO_URL:-https://github.com/themarkroberts/mrc-refresh-mcp.git}"

log() { printf "\033[1;36m[install]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[warn]\033[0m %s\n" "$*" >&2; }
die() { printf "\033[1;31m[error]\033[0m %s\n" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root"
command -v apt-get >/dev/null || die "this script assumes Debian/Ubuntu (apt-get not found)"
id mrc >/dev/null 2>&1 || die "user 'mrc' does not exist — is this the right server?"
[[ -x /home/mrc/mrc-proxy/bin/mrc-refresh ]] || warn "/home/mrc/mrc-proxy/bin/mrc-refresh not found or not executable — service will start, but refreshes will fail until that exists"

log "1/8 installing system packages (python3, venv, git, curl)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git curl ca-certificates debian-keyring debian-archive-keyring apt-transport-https

log "2/8 installing Caddy (from official repo if not present)"
if ! command -v caddy >/dev/null; then
	curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
		| gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
	curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
		> /etc/apt/sources.list.d/caddy-stable.list
	apt-get update -qq
	apt-get install -y -qq caddy
else
	log "    caddy already installed: $(caddy version | head -1)"
fi

log "3/8 cloning/updating $REPO_URL into $APP_DIR"
if [[ -d "$APP_DIR/.git" ]]; then
	git -C "$APP_DIR" fetch --quiet origin
	git -C "$APP_DIR" reset --hard --quiet origin/main
else
	git clone --quiet "$REPO_URL" "$APP_DIR"
fi
chown -R mrc:mrc "$APP_DIR"

log "4/8 setting up Python venv and dependencies"
sudo -u mrc python3 -m venv "$APP_DIR/venv"
sudo -u mrc "$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
sudo -u mrc "$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

log "5/8 setting up $CONFIG_DIR and tokens file"
# Owned by root (only root can write/issue tokens), group-readable by mrc
# (so the service user can load tokens.yml on every request). Mode 0750/0640
# keeps "world" out entirely.
mkdir -p "$CONFIG_DIR"
chown root:mrc "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR"
if [[ ! -f "$TOKENS_FILE" ]]; then
	cat > "$TOKENS_FILE" <<'EOF'
# Bearer token -> contractor name. See tokens.example.yml in the repo.
# Issue a new token with: /opt/mrc-refresh-mcp/scripts/issue-token.sh <name>
EOF
	log "    created empty $TOKENS_FILE — issue tokens with scripts/issue-token.sh"
else
	log "    $TOKENS_FILE already exists — leaving alone"
fi
# Always re-assert ownership/mode in case a previous install left them wrong.
chown root:mrc "$TOKENS_FILE"
chmod 0640 "$TOKENS_FILE"

log "6/8 installing systemd unit"
install -m 0644 "$APP_DIR/deploy/mrc-refresh-mcp.service" "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload
systemctl enable --quiet "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
sleep 2
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
	systemctl status --no-pager "$SERVICE_NAME" | tail -20
	die "$SERVICE_NAME failed to start"
fi

log "7/8 installing Caddy config for $DOMAIN"
mkdir -p /var/log/caddy
chown caddy:caddy /var/log/caddy 2>/dev/null || true
# Render Caddyfile with the actual domain (in case it was overridden).
sed "s/mcp\.markroberts\.io/$DOMAIN/g" "$APP_DIR/deploy/Caddyfile" > /etc/caddy/Caddyfile
systemctl reload caddy || systemctl restart caddy

log "8/8 opening firewall ports (UFW only — DigitalOcean cloud firewall is separate)"
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
	ufw allow 80/tcp  >/dev/null 2>&1 || true
	ufw allow 443/tcp >/dev/null 2>&1 || true
	log "    UFW: 80, 443 allowed"
else
	log "    UFW not active — skipping. If DigitalOcean cloud firewall is in front, allow 80/tcp and 443/tcp there."
fi

cat <<EOF

════════════════════════════════════════════════════════════════════
  Install complete.
════════════════════════════════════════════════════════════════════

  Service:    systemctl status $SERVICE_NAME
  Health:     curl -s http://127.0.0.1:8765/healthz
  Public:     https://$DOMAIN/healthz   (after DNS + cert)
  Caddy log:  journalctl -u caddy -f
  App log:    journalctl -u $SERVICE_NAME -f
  Audit log:  tail -f /home/mrc/mrc-proxy/logs/contractor-access.log

Next steps:
  1. Confirm DNS: dig +short $DOMAIN  (should return this server's IP)
  2. If the DigitalOcean cloud firewall is on, open 80 and 443 in the panel.
  3. Issue a contractor token:  $APP_DIR/scripts/issue-token.sh anton
  4. Verify externally:         curl -s https://$DOMAIN/healthz   (should return "ok")

EOF
