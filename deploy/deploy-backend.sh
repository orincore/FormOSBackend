#!/usr/bin/env bash
# Deploys the FormOS backend to the VPS: code, production .env, PM2, Nginx and an HTTPS certificate.
#
# Run it from the backend folder, on your own machine:   bash deploy/deploy-backend.sh
# It asks for the server password once (one SSH connection is kept open and reused). The password is typed by you
# and is never stored in this file. Safe to run again: later runs update the code and restart the app.
set -euo pipefail

HOST="${HOST:-root@200.97.163.159}"
DOMAIN="${DOMAIN:-api.formos.online}"
SITE_URL="${SITE_URL:-https://www.formos.online}"
APP_DIR="/opt/formos-backend"
PORT_APP="$(grep -E '^PORT=' .env | cut -d= -f2 | tr -d '\r' || true)"; PORT_APP="${PORT_APP:-5001}"
SOCK="$HOME/.ssh/formos-deploy.sock"
PROD_ENV=""

[ -f .env ] || { echo "Run this from the backend folder (no .env found here)."; exit 1; }
[ -f server.js ] || { echo "Run this from the backend folder (no server.js found here)."; exit 1; }

echo "==> Connecting to $HOST (enter the server password when asked)"
ssh -o ControlMaster=yes -o ControlPath="$SOCK" -o ControlPersist=45m -o StrictHostKeyChecking=accept-new -fN "$HOST"
trap 'ssh -o ControlPath="$SOCK" -O exit "$HOST" 2>/dev/null || true; [ -z "$PROD_ENV" ] || rm -f "$PROD_ENV"' EXIT
SSH=(ssh -o ControlPath="$SOCK" "$HOST")

echo "==> Checking that $DOMAIN points at this server"
SERVER_IP="${HOST#*@}"
DNS_IP="$(dig +short "$DOMAIN" A 2>/dev/null | tail -1 || true)"
echo "    DNS says: ${DNS_IP:-unknown}   server: $SERVER_IP"
[ "${DNS_IP:-}" = "$SERVER_IP" ] || echo "    Warning: DNS does not match yet. HTTPS setup will fail until it does."

echo "==> Preparing the production .env (only the domain settings change)"
PROD_ENV="$(mktemp)"
sed -E \
  -e "s#^NODE_ENV=.*#NODE_ENV=production#" \
  -e "s#^FRONTEND_URL=.*#FRONTEND_URL=$SITE_URL#" \
  -e "s#^OAUTH_FRONTEND_CALLBACK_URL=.*#OAUTH_FRONTEND_CALLBACK_URL=$SITE_URL/auth/callback#" \
  -e "s#^GOOGLE_CALLBACK_URL=.*#GOOGLE_CALLBACK_URL=https://$DOMAIN/api/auth/google/callback#" \
  -e "s#^GITHUB_CALLBACK_URL=.*#GITHUB_CALLBACK_URL=https://$DOMAIN/api/auth/github/callback#" \
  -e "s#^ALLOWED_ORIGINS=.*#ALLOWED_ORIGINS=https://formos.online,https://www.formos.online,https://$DOMAIN#" \
  .env > "$PROD_ENV"
chmod 600 "$PROD_ENV"

echo "==> Installing system packages (Node 20, PM2, Nginx, Certbot, OCR tools, Chrome)"
"${SSH[@]}" 'bash -s' <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends curl ca-certificates gnupg git rsync nginx certbot python3-certbot-nginx \
  ghostscript graphicsmagick tesseract-ocr fonts-liberation dnsutils

if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 20 ]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi
command -v pm2 >/dev/null || npm install -g pm2

# The WhatsApp assistant drives headless Chrome. Debian has a chromium package; Ubuntu only has a snap, so use Chrome there.
if ! command -v chromium >/dev/null && ! command -v google-chrome-stable >/dev/null; then
  if apt-get install -y chromium 2>/dev/null; then :; else
    curl -fsSL https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -o /tmp/chrome.deb
    apt-get install -y /tmp/chrome.deb
  fi
fi
mkdir -p /opt/formos-backend
REMOTE

echo "==> Uploading the code"
rsync -az --delete -e "ssh -o ControlPath=$SOCK" \
  --exclude node_modules --exclude .git --exclude .env --exclude uploads --exclude '.wwebjs_*' --exclude .DS_Store \
  ./ "$HOST:$APP_DIR/"
rsync -az -e "ssh -o ControlPath=$SOCK" "$PROD_ENV" "$HOST:$APP_DIR/.env.incoming"

echo "==> Installing dependencies, starting the app with PM2, setting up Nginx"
"${SSH[@]}" "APP_DIR=$APP_DIR DOMAIN=$DOMAIN PORT_APP=$PORT_APP bash -s" <<'REMOTE'
set -euo pipefail
cd "$APP_DIR"

# .env: the new domain settings, plus where Chrome lives on this machine.
mv .env.incoming .env
chmod 600 .env
CHROME="$(command -v chromium || command -v google-chrome-stable || true)"
grep -v '^PUPPETEER_EXECUTABLE_PATH=' .env > .env.tmp || true
[ -n "$CHROME" ] && echo "PUPPETEER_EXECUTABLE_PATH=$CHROME" >> .env.tmp
mv .env.tmp .env && chmod 600 .env
mkdir -p uploads

PUPPETEER_SKIP_DOWNLOAD=true npm ci --omit=dev

pm2 describe formos-backend >/dev/null 2>&1 && pm2 reload formos-backend --update-env || pm2 start server.js --name formos-backend --time
pm2 save
pm2 startup systemd -u root --hp /root >/dev/null 2>&1 || true

cat > /etc/nginx/sites-available/formos-api <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    client_max_body_size 20m;

    location / {
        proxy_pass http://127.0.0.1:$PORT_APP;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 180s;
        proxy_send_timeout 180s;
    }
}
NGINX
ln -sf /etc/nginx/sites-available/formos-api /etc/nginx/sites-enabled/formos-api
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow 'Nginx Full' >/dev/null; ufw allow OpenSSH >/dev/null; fi

# HTTPS certificate (renews by itself). Skipped when one already exists.
if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect
fi
systemctl reload nginx

sleep 4
echo "--- pm2"; pm2 status formos-backend --no-color | tail -5
echo "--- health"; curl -sL -o /dev/null -w "local http %{http_code}\n" "http://127.0.0.1:$PORT_APP/api/health" || true
REMOTE

echo "==> Checking from here"
curl -sL -o /dev/null -w "https://$DOMAIN/api/health -> HTTP %{http_code}\n" "https://$DOMAIN/api/health" || true
echo "Done. Logs on the server: pm2 logs formos-backend"
