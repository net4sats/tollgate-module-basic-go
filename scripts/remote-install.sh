#!/bin/sh
# remote-install.sh — Safely install a tollgate-wrt package on a remote OpenWrt
# router over SSH without risking loss of connectivity.
#
# USAGE:
#   ./scripts/remote-install.sh <router-ip> <path-to-ipk-or-apk> [ssh-key] [ssh-user]
#
# EXAMPLES:
#   ./scripts/remote-install.sh 10.89.4.51 /tmp/tollgate-ipk/tollgate-wrt_*.ipk
#   ./scripts/remote-install.sh 10.171.103.1 /tmp/tollgate.apk ~/.ssh/id_ed25519 root
#
# WHAT IT DOES:
#   1. Transfers the package to /tmp/ on the router
#   2. Installs with opkg (ipk) or apk
#   3. Restarts only tollgate-wrt and nodogsplash (NOT network or wifi)
#   4. Waits for SSH to recover and verifies the service is running
#
# WHY THIS EXISTS:
#   The package postinst used to run 'network restart' which tears down all
#   interfaces including the one SSH uses. This script is a safe alternative
#   that never touches the network stack.

set -eu

ROUTER_IP="${1:?Usage: $0 <router-ip> <package-file> [ssh-key] [ssh-user]}"
PKG_FILE="${2:?Usage: $0 <router-ip> <package-file> [ssh-key] [ssh-user]}"
SSH_KEY="${3:-~/.ssh/id_ed25519}"
SSH_USER="${4:-root}"

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -i $SSH_KEY"
REMOTE_PKG="/tmp/$(basename "$PKG_FILE")"

echo "=== TollGate Remote Install ==="
echo "Router: $SSH_USER@$ROUTER_IP"
echo "Package: $PKG_FILE"
echo ""

# 1. Transfer package
echo "[1/4] Transferring package..."
scp -O $SSH_OPTS "$PKG_FILE" "$SSH_USER@$ROUTER_IP:$REMOTE_PKG"

# 2. Install
echo "[2/4] Installing package..."
case "$REMOTE_PKG" in
    *.ipk)
        ssh $SSH_OPTS "$SSH_USER@$ROUTER_IP" \
            "opkg install --force-reinstall '$REMOTE_PKG'" || {
            echo "ERROR: opkg install failed"
            exit 1
        }
        ;;
    *.apk)
        ssh $SSH_OPTS "$SSH_USER@$ROUTER_IP" \
            "apk add --allow-untrusted '$REMOTE_PKG'" || {
            echo "ERROR: apk install failed"
            exit 1
        }
        ;;
    *)
        echo "ERROR: Unknown package format (expected .ipk or .apk)"
        exit 1
        ;;
esac

# 3. Restart services (NOT network or wifi)
echo "[3/4] Restarting tollgate-wrt and nodogsplash..."
ssh $SSH_OPTS "$SSH_USER@$ROUTER_IP" "\
    /etc/init.d/nodogsplash restart 2>/dev/null || true; \
    /etc/init.d/tollgate-wrt enable 2>/dev/null || true; \
    /etc/init.d/tollgate-wrt restart 2>/dev/null || true"

# 4. Verify
echo "[4/4] Verifying service..."
sleep 2
if ssh $SSH_OPTS "$SSH_USER@$ROUTER_IP" "pgrep -f tollgate-wrt >/dev/null" 2>/dev/null; then
    VERSION=$(ssh $SSH_OPTS "$SSH_USER@$ROUTER_IP" "opkg list-installed tollgate-wrt 2>/dev/null || apk list --installed tollgate-wrt 2>/dev/null" 2>/dev/null | head -1)
    echo ""
    echo "SUCCESS: tollgate-wrt is running"
    echo "Version: $VERSION"
else
    echo ""
    echo "WARNING: tollgate-wrt process not found — check 'logread -e tollgate' on the router"
    exit 1
fi
