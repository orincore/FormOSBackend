#!/bin/bash
# Update the production backend: pull, restart, health check. The SSH password is read from SSHPASS (never stored here).
# Usage: SSHPASS='...' ./scripts/deploy-vps.sh [path/to/chrome-extension.zip]
set -u
HOST=root@200.97.163.159
SSH=(sshpass -e ssh -n -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ServerAliveInterval=5 -o ServerAliveCountMax=3)
[ -n "${SSHPASS:-}" ] || { echo "Set SSHPASS first"; exit 1; }

echo "== pull"
"${SSH[@]}" $HOST 'cd /root/formos-backend && git pull 2>&1 | tail -3; git log --oneline | head -1'

echo "== restart (detached so pm2 cannot hold the session open)"
"${SSH[@]}" $HOST 'nohup sh -c "pm2 restart formos-backend" >/tmp/pm2-restart.log 2>&1 < /dev/null &' 
sleep 12

echo "== status"
"${SSH[@]}" $HOST 'pm2 list 2>&1 | grep formos | cut -c1-110; curl -s -m 8 -o /dev/null -w "health %{http_code}\n" http://127.0.0.1:5101/api/health'

if [ -n "${1:-}" ]; then
  echo "== extension zip"
  sshpass -e scp -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o PreferredAuthentications=password -o PubkeyAuthentication=no "$1" $HOST:/root/chrome-extension.zip
  "${SSH[@]}" $HOST 'curl -s -m 30 -X POST http://127.0.0.1:5101/api/extension/upload | cut -c1-200; echo; shasum /root/chrome-extension.zip | cut -c1-16'
  shasum "$1" | cut -c1-16
fi
echo "== done"
