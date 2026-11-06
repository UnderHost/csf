#!/bin/sh
###############################################################################
# CSF 2.0 - Core Shield Firewall
# remove-legacy-csf.sh - safely uninstall legacy CSF (ConfigServer Security &
# Firewall, v15.x and earlier) AFTER its configuration has been migrated.
#
# ORDER MATTERS: the caller (install.sh) must have already run `csf2 migrate`
# so /etc/csf now holds the migrated CSF 2.0 config. This script therefore
# preserves /etc/csf and removes only the legacy binaries, services, WHM plugin,
# cron jobs, and the legacy iptables/ipset firewall state.
#
# It removes only firewall structures attributable to legacy CSF - it never
# flushes unrelated rules belonging to other software.
#
# Copyright (C) 2026 CSF - Core Shield Firewall. GNU GPL v3.
###############################################################################
set -e
echo "==> Removing legacy CSF (ConfigServer Security & Firewall)"

# 1) Tear down the legacy firewall cleanly using the legacy tool itself, which
#    knows exactly which iptables rules and ipset sets it created.
if [ -x /usr/sbin/csf ]; then
    echo "    csf -x (disable) + csf -f (flush legacy rules)"
    /usr/sbin/csf -x  >/dev/null 2>&1 || true
    /usr/sbin/csf -f  >/dev/null 2>&1 || true
fi

# 2) Stop + disable the legacy services.
for svc in lfd csf; do
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop    "$svc" >/dev/null 2>&1 || true
        systemctl disable "$svc" >/dev/null 2>&1 || true
    fi
    [ -x "/etc/init.d/$svc" ] && "/etc/init.d/$svc" stop >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/lfd.service /etc/systemd/system/csf.service 2>/dev/null || true
rm -f /usr/lib/systemd/system/lfd.service 2>/dev/null || true

# 3) Remove any ipset sets that legacy CSF created (names are CSF-specific:
#    chain_*, bl_*, cc_*, new_*, deny_*, allow_*, GDENY, etc.). Only sets whose
#    names match these legacy CSF prefixes are touched.
if command -v ipset >/dev/null 2>&1; then
    ipset list -name 2>/dev/null | grep -E '^(chain_|bl_|cc_|new_|deny_|allow_|tempdeny|tempallow|GDENY|MESSENGER)' | while read -r set; do
        echo "    removing legacy ipset: $set"
        ipset flush "$set" 2>/dev/null || true
        ipset destroy "$set" 2>/dev/null || true
    done
fi

# 4) Remove legacy cron jobs.
rm -f /etc/cron.d/csf_update /etc/cron.d/lfd_update /etc/cron.d/csf 2>/dev/null || true

# 5) Remove the legacy WHM plugin (cPanel).
if [ -d /usr/local/cpanel ]; then
    if [ -x /usr/local/cpanel/bin/unregister_appconfig ]; then
        /usr/local/cpanel/bin/unregister_appconfig csf >/dev/null 2>&1 || true
    fi
    rm -rf /usr/local/cpanel/whostmgr/docroot/cgi/configserver/csf.cgi \
           /usr/local/cpanel/whostmgr/docroot/cgi/configserver/csf \
           /usr/local/cpanel/whostmgr/docroot/addon_plugins/csf_small.png 2>/dev/null || true
fi

# 6) Remove legacy binaries + legacy Perl modules, PRESERVING /etc/csf (migrated
#    config) and the new /usr/local/csf/bin + /usr/local/csf/lib/CSF2 tree.
rm -f /usr/sbin/csf /usr/sbin/lfd 2>/dev/null || true
rm -rf /usr/local/csf/lib/ConfigServer \
       /usr/local/csf/lib/Crypt /usr/local/csf/lib/Net /usr/local/csf/lib/HTTP \
       /usr/local/csf/lib/JSON /usr/local/csf/lib/Module 2>/dev/null || true
# legacy top-level perl scripts under /usr/local/csf (do not touch bin/ or lib/CSF2)
for f in csf.pl lfd.pl os.pl csftest.pl migratedata.sh; do
    rm -f "/usr/local/csf/$f" 2>/dev/null || true
done

echo "==> Legacy CSF removed. /etc/csf (migrated config) preserved."
echo "    Verify no stale CSF rules remain: nft list ruleset | grep -i csf ; iptables -S | grep -i csf"
