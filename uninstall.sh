#!/bin/sh
###############################################################################
# CSF 2.0 - Core Shield Firewall - uninstaller.
#
# Cleanly removes CSF 2.0. Most importantly, it removes the nftables table so
# NO stale CSF rules are left loaded in the kernel. Configuration and backups
# under /etc/csf are preserved unless --purge is given.
#
# Usage: ./uninstall.sh [--purge]
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################
set -e
PREFIX="/usr/local/csf"
ETC="/etc/csf"
PURGE=0
[ "$1" = "--purge" ] && PURGE=1

[ "$(id -u)" = "0" ] || { echo "FAILED: run as root"; exit 1; }
echo "==> Uninstalling CSF 2.0"

# 1) remove the nftables table (no stale rules left behind)
if [ -x "$PREFIX/bin/csf2" ]; then
    "$PREFIX/bin/csf2" --initdown >/dev/null 2>&1 || true
elif command -v nft >/dev/null 2>&1; then
    nft delete table inet csf 2>/dev/null || true
fi

# 2) detach optional XDP layer if present
if [ -f "$PREFIX/xdp/load-xdp.sh" ]; then
    for i in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1); do
        sh "$PREFIX/xdp/load-xdp.sh" --unload "$i" >/dev/null 2>&1 || true
    done
fi

# 3) services
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop    csf.service lfd.service csf2-ui.service >/dev/null 2>&1 || true
    systemctl disable csf.service lfd.service csf2-ui.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/csf.service /etc/systemd/system/lfd.service \
          /etc/systemd/system/csf2-ui.service /etc/cron.d/csf-ti /etc/cron.d/csf-scan
    systemctl daemon-reload
fi

# 4) WHM plugin
if [ -x /usr/local/cpanel/bin/unregister_appconfig ]; then
    /usr/local/cpanel/bin/unregister_appconfig cpanelshield >/dev/null 2>&1 || true
    /usr/local/cpanel/bin/unregister_appconfig csf2 >/dev/null 2>&1 || true
fi
rm -rf /usr/local/cpanel/whostmgr/docroot/cgi/cpanelshield \
       /usr/local/cpanel/whostmgr/docroot/cgi/configserver2 2>/dev/null || true

# 5) binaries, libs, symlinks
rm -f /usr/sbin/csf /usr/sbin/csf2 /usr/sbin/lfd2 2>/dev/null || true
rm -rf "$PREFIX/bin/csf2" "$PREFIX/bin/lfd2" "$PREFIX/bin/csf2-ui" "$PREFIX/ui" \
       "$PREFIX/lib/CSF2" "$PREFIX/xdp" 2>/dev/null || true
# a CloudPanel reverse-proxy site created for the UI is left in place:
# remove it in CloudPanel (Sites) if it is no longer needed.

# 6) config / state
if [ "$PURGE" = "1" ]; then
    echo "    --purge: removing $ETC and state"
    rm -rf "$ETC" /var/lib/csf 2>/dev/null || true
else
    echo "    preserving $ETC (config + backups). Use --purge to remove."
fi

echo "==> Done. Verify nothing remains:"
echo "    nft list ruleset | grep -i csf   (should print nothing)"
