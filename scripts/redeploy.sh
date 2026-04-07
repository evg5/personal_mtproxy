#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[1/4] Building production release"
make

echo "[2/4] Stopping service"
systemctl stop personal_mtproxy

echo "[3/4] Installing release"
make install

echo "[4/4] Starting service"
systemctl start personal_mtproxy

echo
systemctl --no-pager --full status personal_mtproxy
