#!/bin/bash
# Certbot deploy hook for personal_mtproxy.
# Installed to /etc/letsencrypt/renewal-hooks/deploy/ by `make install`.
# Runs automatically after every successful certificate renewal.
# Also triggered manually by `make install` when a certificate already exists.
#
# The target domain is encoded in the cert-lineage symlink — no domain is
# hardcoded here, so the script works correctly even when multiple certificates
# are present on the same host.

DATADIR=/var/lib/personal_mtproxy
LINEAGE_LINK="$DATADIR/cert-lineage"
SERVICE=personal_mtproxy

# Resolve which lineage this installation watches.
expected=$(readlink "$LINEAGE_LINK" 2>/dev/null) || {
    echo "personal_mtproxy deploy hook: $LINEAGE_LINK not found, skipping." >&2
    exit 0
}

# Certbot sets $RENEWED_LINEAGE for automatic invocations.
# make install sets it manually for the initial copy.
[ "${RENEWED_LINEAGE}" = "$expected" ] || exit 0

install -o "$SERVICE" -g "$SERVICE" -m 600 "$RENEWED_LINEAGE/privkey.pem"   "$DATADIR/privkey.pem"
install -o "$SERVICE" -g "$SERVICE" -m 644 "$RENEWED_LINEAGE/fullchain.pem" "$DATADIR/fullchain.pem"

echo "personal_mtproxy deploy hook: certificates copied to $DATADIR/"

systemctl reload-or-restart "$SERVICE" 2>/dev/null || true
