#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

SERVICE_USER=personal_mtproxy
SERVICE_GROUP=personal_mtproxy
DATA_DIR=/var/lib/personal_mtproxy
LOG_DIR=/var/log/personal_mtproxy

echo "[1/4] Building production release"
make

echo "[2/4] Stopping service"
systemctl stop personal_mtproxy

echo "[3/4] Installing release"
make install

echo "[3.5/4] Restoring runtime file ownership"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR" "$LOG_DIR"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR" "$LOG_DIR"

echo "[4/4] Starting service"
systemctl start personal_mtproxy

echo
systemctl --no-pager --full status personal_mtproxy
