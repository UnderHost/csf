#!/bin/sh
###############################################################################
# CSF 2.0 - Core Shield Firewall - installer / upgrader.
#
# Full flow, safe by construction:
#   1. verify root, perl, nftables
#   2. run the test suite (abort on failure)
#   3. install CSF 2.0 files to /usr/local/csf (new tree; does not clobber
#      legacy Perl modules, which live in a different subdir)
#   4. detect legacy CSF v15 and, if present:
#        a. migrate its config (backup + convert) using the NEW csf2 binary
#        b. remove the legacy install (services, WHM plugin, cron, ipset/iptables
#           state) while PRESERVING the migrated /etc/csf
#   5. install systemd units + register the WHM plugin (AppConfig)
#   6. generate + validate the nftables ruleset in TESTING mode (non-enforcing)
#   7. health check
#
# The working firewall is never torn down until the replacement ruleset has
# validated. Enabling enforcement (TESTING=0) is left to the admin.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="/usr/local/csf"
ETC="/etc/csf"
VAR="/var/lib/csf"

# --- colours (only when stdout is a terminal) ---
if [ -t 1 ]; then
    C_RESET='\033[0m'; C_B='\033[1m'; C_BLUE='\033[38;5;63m'; C_CYAN='\033[38;5;80m'
    C_GREEN='\033[38;5;42m'; C_YEL='\033[38;5;214m'; C_RED='\033[38;5;203m'; C_DIM='\033[2m'
else
    C_RESET=; C_B=; C_BLUE=; C_CYAN=; C_GREEN=; C_YEL=; C_RED=; C_DIM=
fi
log()  { printf "${C_BLUE}${C_B}==>${C_RESET} %s\n" "$*"; }
ok()   { printf "    ${C_GREEN}${C_B}OK${C_RESET}  %s\n" "$*"; }
warn() { printf "    ${C_YEL}${C_B}!!${C_RESET}  %s\n" "$*"; }
err()  { printf "    ${C_RED}${C_B}XX${C_RESET}  %s\n" "$*"; }

banner() {
    printf "\n${C_BLUE}${C_B}"
    printf "      ██████╗ ███████╗███████╗\n"
    printf "     ██╔════╝ ██╔════╝██╔════╝\n"
    printf "     ██║      ███████╗█████╗    ${C_GREEN}▄▟█${C_BLUE}\n"
    printf "     ██║      ╚════██║██╔══╝\n"
    printf "     ╚██████╗ ███████║██║\n"
    printf "      ╚═════╝ ╚══════╝╚═╝${C_RESET}\n"
    printf "     ${C_B}Core Shield Firewall${C_RESET}  ${C_DIM}· CSF 2.0 · UnderShield${C_RESET}\n\n"
}
box() {  # box "COLOR" "line1" "line2..."
    _c="$1"; shift
    printf "\n${_c}${C_B}    +---------------------------------------------------------+${C_RESET}\n"
    for _l in "$@"; do printf "${_c}${C_B}    |${C_RESET}  %-53s ${_c}${C_B}|${C_RESET}\n" "$_l"; done
    printf "${_c}${C_B}    +---------------------------------------------------------+${C_RESET}\n\n"
}

banner

# 1) prerequisites
[ "$(id -u)" = "0" ] || { err "must run as root (UID 0)"; exit 1; }
# Minimal images ship only part of Perl (Debian/Ubuntu "perl-base", EL
# "perl-interpreter"), so the core modules CSF uses may be missing. Install
# the full "perl" package and nftables when needed (CSF_NO_DEPS=1 skips this).
PERL_MODS="Digest::SHA Test::More FindBin File::Temp File::Path File::Copy File::Find Fcntl POSIX Socket Time::Local MIME::Base64 IPC::Open3 IO::Select IO::Socket::INET IO::Uncompress::Unzip"
deps_ok() {
    command -v nft >/dev/null 2>&1 && command -v perl >/dev/null 2>&1 \
        && perl -e 'for (@ARGV) { eval "require $_; 1" or exit 1 }' $PERL_MODS 2>/dev/null
}
if ! deps_ok && [ "${CSF_NO_DEPS:-0}" != "1" ]; then
    log "Installing missing dependencies (perl core modules, nftables)"
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q perl nftables >/dev/null 2>&1 \
            || { apt-get update -q >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -q perl nftables >/dev/null 2>&1; }
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q perl nftables >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q perl nftables >/dev/null 2>&1
    fi
fi
# SELinux (EL8/CloudLinux 8): copied files can keep a generic label (default_t);
# systemd then cannot read the units at all ("Unit csf.service does not exist").
relabel() { command -v restorecon >/dev/null 2>&1 && restorecon -RF "$@" >/dev/null 2>&1; return 0; }
if ! deps_ok; then
    command -v nft >/dev/null 2>&1 || err "nftables (nft) is missing"
    for _m in $PERL_MODS; do perl -e "require $_m" 2>/dev/null || err "Perl module $_m is missing"; done
    echo "FAILED: install the full perl package and nftables (apt-get install -y perl nftables / dnf install -y perl nftables), then run install.sh again"
    exit 1
fi
# hosting platform: decides port presets and where the UI lives
if [ -d /usr/local/cpanel ]; then PLATFORM=cpanel
elif [ -d /usr/local/directadmin ]; then PLATFORM=directadmin
elif [ -e /usr/bin/clpctl ] || [ -d /home/clp ]; then PLATFORM=cloudpanel
else PLATFORM=generic; fi
case "$PLATFORM" in
    cpanel)      log "cPanel detected: $(cat /usr/local/cpanel/version 2>/dev/null) - UI: WHM plugin" ;;
    cloudpanel)  log "CloudPanel detected - UI: standalone (csf2-ui) behind a CloudPanel reverse-proxy site" ;;
    directadmin) log "DirectAdmin detected - UI: standalone (csf2-ui) until the DirectAdmin plugin ships" ;;
    *)           log "No control panel detected - UI: standalone (csf2-ui)" ;;
esac
# a second firewall manager would fight CSF over the same packets
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    warn "ufw is ACTIVE. CSF 2.x manages the firewall itself - disable ufw once CSF is enforcing: ufw disable"
fi
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    warn "firewalld is ACTIVE. CSF 2.x manages the firewall itself - disable it once CSF is enforcing: systemctl disable --now firewalld"
fi

# 2) test suite gate
log "Running test suite"
sh "$HERE/run-tests.sh" || { echo "FAILED: tests did not pass; aborting"; exit 1; }

# 3) install new files (safe alongside legacy: CSF2 lib is a separate subdir)
log "Installing CSF 2.0 to $PREFIX"
mkdir -p "$PREFIX/lib" "$PREFIX/bin" "$VAR" "$ETC"
# Replace the module tree wholesale so an in-place upgrade lands modules at
# $PREFIX/lib/CSF2/*.pm (never nested as CSF2/CSF2) and stale modules are pruned.
rm -rf "$PREFIX/lib/CSF2"
cp -a "$HERE/lib/CSF2" "$PREFIX/lib/"
install -m 0755 "$HERE/bin/csf2" "$PREFIX/bin/csf2"
install -m 0755 "$HERE/bin/lfd2" "$PREFIX/bin/lfd2"
# config-editor help reference (descriptions for the WHM Configuration tab)
install -m 0644 "$HERE/etc/csf.conf.help" "$PREFIX/csf.conf.help" 2>/dev/null || true
mkdir -p "$PREFIX/xdp"
cp -a "$HERE/xdp/." "$PREFIX/xdp/" 2>/dev/null || true

# 4) legacy detection + migration + removal.
#    An existing CSF 2.x install (version.txt starts with "2.") is an UPGRADE -
#    skip migration/removal. Legacy = a non-2.x CSF is present. Note /usr/sbin/csf
#    is our own symlink after a 2.x install, so it cannot be the legacy signal.
LEGACY=0
if [ -e "$ETC/version.txt" ] && grep -q '^2\.' "$ETC/version.txt" 2>/dev/null; then
    log "Existing CSF 2.x detected ($(cat $ETC/version.txt)) - upgrading in place"
elif { [ -e "$ETC/version.txt" ] && ! grep -q '^2\.' "$ETC/version.txt" 2>/dev/null; } || [ -e /usr/local/csf/csf.pl ]; then
    LEGACY=1
fi

if [ "$LEGACY" = "1" ]; then
    log "Legacy CSF detected (version: $(cat $ETC/version.txt 2>/dev/null || echo unknown))"
    # Tear down the legacy firewall FIRST, while its own csf.conf is still
    # intact, so the legacy tool flushes its rules correctly.
    if [ -x /usr/sbin/csf ]; then
        log "Tearing down legacy firewall (csf -x; csf -f)"
        /usr/sbin/csf -x >/dev/null 2>&1 || true
        /usr/sbin/csf -f >/dev/null 2>&1 || true
    fi
    log "Migrating legacy configuration (backup + convert)"
    "$PREFIX/bin/csf2" migrate
    log "Removing legacy CSF (services, plugin, ipset, binaries)"
    sh "$HERE/scripts/remove-legacy-csf.sh"
else
    log "No legacy CSF detected - fresh install"
    if [ ! -e "$ETC/csf.conf" ]; then
        install -m 0600 "$HERE/etc/csf.conf" "$ETC/csf.conf"
        install -m 0644 "$HERE/etc/csf.logfiles" "$ETC/csf.logfiles"
        install -m 0644 "$HERE/etc/csf.ignore" "$ETC/csf.ignore"
        touch "$ETC/csf.allow" "$ETC/csf.deny"
        FRESH_CONFIG=1
    fi
fi

# On a genuinely fresh config, auto-configure ports for THIS cPanel server:
# detect the real SSH port + cPanel service ports so the firewall is correctly
# set up (and lockout-safe) on every cPanel box, not just one with default
# ports. Upgrades and migrations keep the admin's existing ports untouched.
if [ "${FRESH_CONFIG:-0}" = "1" ] && [ "$PLATFORM" = "cpanel" ]; then
    log "Configuring cPanel service ports (auto-detect SSH + cPanel ports)"
    "$PREFIX/bin/csf2" --cpanel-setup || true
elif [ "${FRESH_CONFIG:-0}" = "1" ]; then
    _p=generic; [ "$PLATFORM" = "cloudpanel" ] && _p=cloudpanel
    log "Configuring $_p ports (auto-detect SSH port)"
    "$PREFIX/bin/csf2" --platform-setup "$_p" || true
fi

# Like legacy CSF: never lock out the administrator. The address of the SSH
# session running the installer goes on the allow list (also under sudo, which
# drops SSH_CLIENT). Updates run from cron or the web UI have no session: skipped.
ADMIN_IP=$(printf '%s' "${SSH_CLIENT:-${SSH_CONNECTION:-}}" | awk '{print $1}')
[ -n "$ADMIN_IP" ] || ADMIN_IP=$(who -m 2>/dev/null | sed -n 's/.*(\([0-9a-fA-F.:]*\)).*/\1/p' | head -1)
if [ -n "$ADMIN_IP" ] && ! grep -q "^$ADMIN_IP[ #]" "$ETC/csf.allow" 2>/dev/null; then
    "$PREFIX/bin/csf2" -a "$ADMIN_IP" "Administrator (SSH session used to install CSF)" >/dev/null 2>&1 \
        && ok "your SSH address $ADMIN_IP is on the allow list (never blocked)"
fi

# preserve CLI muscle memory: `csf` and `lfd` names point at the new tools
ln -sf "$PREFIX/bin/csf2" /usr/sbin/csf
ln -sf "$PREFIX/bin/csf2" /usr/sbin/csf2
ln -sf "$PREFIX/bin/lfd2" /usr/sbin/lfd2
# the version comes from the single VERSION file of the package
install -m 0644 "$HERE/VERSION" "$PREFIX/VERSION"
tr -d ' \r\n' < "$HERE/VERSION" > "$ETC/version.txt"; echo >> "$ETC/version.txt"

# 5) systemd units + WHM plugin
if command -v systemctl >/dev/null 2>&1; then
    log "Installing systemd units"
    install -m 0644 "$HERE/systemd/csf.service" /etc/systemd/system/csf.service
    install -m 0644 "$HERE/systemd/lfd.service" /etc/systemd/system/lfd.service
    relabel /etc/systemd/system/csf.service /etc/systemd/system/lfd.service "$PREFIX" "$ETC" "$VAR" /usr/sbin/csf /usr/sbin/csf2
    systemctl daemon-reload
fi
if [ -d /usr/local/cpanel ] && [ -x /usr/local/cpanel/bin/register_appconfig ] && [ -f "$HERE/cpanel/csf2.conf" ]; then
    log "Registering WHM plugin via AppConfig (Core Shield Firewall)"
    # clean up any earlier/broken registration from prior installs
    /usr/local/cpanel/bin/unregister_appconfig csf2 >/dev/null 2>&1 || true
    rm -rf /usr/local/cpanel/whostmgr/docroot/cgi/configserver2 2>/dev/null || true
    # install the CGI as cgi/cpanelshield/firewall.cgi
    PLUGDIR=/usr/local/cpanel/whostmgr/docroot/cgi/cpanelshield
    mkdir -p "$PLUGDIR"
    install -m 0755 "$HERE/cpanel/csf2.cgi" "$PLUGDIR/firewall.cgi"
    # brand assets served alongside the plugin (WHM header logo + menu icon)
    install -m 0644 "$HERE/cpanel/logo.png" "$PLUGDIR/logo.png" 2>/dev/null || true
    install -m 0644 "$HERE/cpanel/icon.png" "$PLUGDIR/icon.png" 2>/dev/null || true
    install -m 0644 "$HERE/cpanel/icon-menu.png" \
        /usr/local/cpanel/whostmgr/docroot/addon_plugins/cpanelshield.png 2>/dev/null || true
    # Run the plugin under cPanel's perl so Whostmgr::ACLS / Cpanel::Template load
    # (they are not in system perl's @INC). Without this the plugin renders as a
    # standalone full page instead of inside the WHM chrome.
    if [ -x /usr/local/cpanel/3rdparty/bin/perl ]; then
        sed -i '1s|^#!.*perl.*|#!/usr/local/cpanel/3rdparty/bin/perl|' "$PLUGDIR/firewall.cgi"
    fi
    # WHM master-template wrapper so the plugin renders INSIDE the WHM chrome
    install -m 0644 "$HERE/cpanel/cpanelshield.tmpl" /usr/local/cpanel/whostmgr/docroot/templates/cpanelshield.tmpl 2>/dev/null || true
    /usr/local/cpanel/bin/register_appconfig "$HERE/cpanel/csf2.conf" >/dev/null 2>&1 \
        && log "WHM plugin registered: /cgi/cpanelshield/firewall.cgi" \
        || warn "register_appconfig failed"
fi

# 5a) standalone web UI for servers without WHM. Listens on 127.0.0.1 only;
#     nobody can sign in until an account exists (csf --ui-user add <name>).
if [ "$PLATFORM" != "cpanel" ]; then
    log "Installing the standalone web UI (csf2-ui)"
    mkdir -p "$PREFIX/ui"
    install -m 0700 "$HERE/cpanel/csf2.cgi" "$PREFIX/ui/firewall.cgi"
    sed -i '1s|^#!.*perl.*|#!/usr/bin/perl|' "$PREFIX/ui/firewall.cgi"
    install -m 0644 "$HERE/cpanel/logo.png" "$PREFIX/ui/logo.png" 2>/dev/null || true
    install -m 0700 "$HERE/ui/csf2-ui" "$PREFIX/bin/csf2-ui"
    touch /var/log/csf2-ui.log && chmod 0600 /var/log/csf2-ui.log
    grep -q '^/var/log/csf2-ui.log' "$ETC/csf.logfiles" 2>/dev/null || echo "/var/log/csf2-ui.log" >> "$ETC/csf.logfiles"
    if command -v systemctl >/dev/null 2>&1; then
        install -m 0644 "$HERE/systemd/csf2-ui.service" /etc/systemd/system/csf2-ui.service
        relabel /etc/systemd/system/csf2-ui.service "$PREFIX" /var/log/csf2-ui.log
        systemctl daemon-reload
        systemctl enable csf2-ui.service >/dev/null 2>&1 || true
        UI_RESTART=1   # (re)started at the very end, see below
    fi
    # CloudPanel: optionally publish the UI as an HTTPS reverse-proxy site.
    #   CSF_UI_DOMAIN=fw.example.com sh install.sh
    if [ "$PLATFORM" = "cloudpanel" ] && [ -n "${CSF_UI_DOMAIN:-}" ] && [ -x /usr/bin/clpctl ]; then
        _uiport=$(sed -n 's/^UI_PORT *= *"\{0,1\}\([0-9]*\)"\{0,1\}.*/\1/p' "$ETC/csf.conf" | head -1); _uiport=${_uiport:-6789}
        _siteuser="csfui$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
        _sitepass="$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n' | cut -c1-24)Aa1!"
        log "Creating CloudPanel reverse-proxy site https://$CSF_UI_DOMAIN -> 127.0.0.1:$_uiport"
        if /usr/bin/clpctl site:add:reverse-proxy --domainName="$CSF_UI_DOMAIN" \
              --reverseProxyUrl="http://127.0.0.1:$_uiport" \
              --siteUser="$_siteuser" --siteUserPassword="$_sitepass" >/dev/null 2>&1; then
            ok "site created (site user $_siteuser)"
            UI_PUBLISHED="https://$CSF_UI_DOMAIN"
            /usr/bin/clpctl lets-encrypt:install:certificate --domainName="$CSF_UI_DOMAIN" >/dev/null 2>&1 \
                && ok "Let's Encrypt certificate installed" \
                || warn "certificate not issued yet - point DNS for $CSF_UI_DOMAIN at this server, then: clpctl lets-encrypt:install:certificate --domainName=$CSF_UI_DOMAIN"
        else
            warn "clpctl could not create the site - create it in CloudPanel: Add Site > Reverse Proxy > http://127.0.0.1:$_uiport"
        fi
    fi
    # Proxy key: csf2-ui believes a proxy's visitor address (X-Real-IP) only when
    # the proxy also sends this secret - other local processes cannot read it,
    # so they cannot fake addresses to dodge the sign-in lockout.
    if [ ! -s "$ETC/ui.proxykey" ]; then
        ( umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ETC/ui.proxykey" )
    fi
    chmod 600 "$ETC/ui.proxykey"
    # add it to every nginx site that proxies to the UI (CloudPanel or your own);
    # nginx -t must pass, otherwise the change is undone
    _uiport=$(sed -n 's/^UI_PORT *= *"\{0,1\}\([0-9]*\)"\{0,1\}.*/\1/p' "$ETC/csf.conf" | head -1); _uiport=${_uiport:-6789}
    if command -v nginx >/dev/null 2>&1; then
        _key=$(cat "$ETC/ui.proxykey"); _patched=""
        for _f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
            [ -f "$_f" ] || continue
            grep -q "proxy_pass http://127.0.0.1:$_uiport" "$_f" || continue
            grep -q "X-CSF-Proxy-Key $_key;" "$_f" && continue
            _real=$(readlink -f "$_f")
            cp -p "$_real" "$_real.csf-bak"
            sed -i "/X-CSF-Proxy-Key/d; s#\(proxy_pass http://127.0.0.1:$_uiport;\)#\1\n        proxy_set_header X-CSF-Proxy-Key $_key;#" "$_real"
            _patched="$_patched $_real"
        done
        if [ -n "$_patched" ]; then
            if nginx -t >/dev/null 2>&1; then
                systemctl reload nginx >/dev/null 2>&1 || nginx -s reload >/dev/null 2>&1 || true
                for _r in $_patched; do rm -f "$_r.csf-bak"; done
                ok "nginx sites proxying to the UI now send the proxy key"
            else
                for _r in $_patched; do mv -f "$_r.csf-bak" "$_r"; done
                warn "could not add the proxy key to nginx (nginx -t failed) - see the CSF docs (UI behind a reverse proxy)"
            fi
        fi
    fi
fi

# 5b) Threat Intelligence: install an hourly feed-refresh cron. It is a no-op
#     unless TI_ENABLE=1, so it is safe to install unconditionally.
if [ -d /etc/cron.d ]; then
    cat > /etc/cron.d/csf-ti <<'CRON'
# CSF 2.0 - Threat Intelligence feed refresh (no-op unless TI_ENABLE=1)
17 * * * * root /usr/local/csf/bin/csf2 --ti-update >/dev/null 2>&1
CRON
    log "Threat Intelligence cron installed (/etc/cron.d/csf-ti, hourly)"
    # 2.3: malicious upload scanning, every 5 min + daily signatures (no-op unless SCAN_ENABLE=1)
    cat > /etc/cron.d/csf-scan <<'CRON'
# CSF 2.3 - malicious upload scanning (no-op unless SCAN_ENABLE=1)
*/5 * * * * root /usr/local/csf/bin/csf2 --scan >/dev/null 2>&1
41 4 * * * root /usr/local/csf/bin/csf2 --scan-update --cron >/dev/null 2>&1
CRON
    log "Upload-scanning cron installed (/etc/cron.d/csf-scan; turn on with: csf --scan-setup)"
fi

# 6) load the ruleset. `csf2 -r` honors TESTING: it validates + lockout-guards
#    always, and APPLIES only when TESTING=0. This closes the window where the
#    legacy firewall is gone but the new one is not yet loaded.
log "Loading firewall ruleset"
"$PREFIX/bin/csf2" -r || true

# determine the effective mode for the summary
if grep -qE '^TESTING\s*=\s*"?0"?' "$ETC/csf.conf" 2>/dev/null; then
    MODE="ENFORCING"
else
    MODE="TESTING (ruleset generated, NOT enforcing)"
fi

# 6b) services. When the firewall enforces, LFD must actually RUN: enabling it
#     alone only starts it at the next reboot (servers ran for weeks with no
#     brute-force banning that way). Restarting also makes an update - which
#     re-runs this installer - load the new LFD code. lfd.service requires
#     csf.service, so this starts that too (the same ruleset as just loaded).
LFD_STATE="not started (firewall in TESTING mode)"
if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/lfd.service ]; then
    if [ "$MODE" = "ENFORCING" ]; then
        systemctl enable csf.service lfd.service >/dev/null 2>&1 || true
        if systemctl restart lfd.service >/dev/null 2>&1 && sleep 2 && systemctl is-active --quiet lfd.service; then
            LFD_STATE="running"; ok "LFD running - brute-force detection active"
        else
            LFD_STATE="FAILED - check: systemctl status lfd.service"; warn "LFD did not start - check: systemctl status lfd.service"
        fi
    elif systemctl is-active --quiet lfd.service; then
        systemctl restart lfd.service >/dev/null 2>&1 && LFD_STATE="running" && ok "LFD restarted with the new version"
    fi
fi

# 7) health
log "Health check"
"$PREFIX/bin/csf2" health || true

box "$C_GREEN" \
    "CSF $(cat "$ETC/version.txt" 2>/dev/null) INSTALLED SUCCESSFULLY" \
    "Core Shield Firewall is protecting this server." \
    "Mode: $MODE"

cat <<EOF
    Legacy CSF migrated: $( [ "$LEGACY" = 1 ] && echo yes || echo "n/a (fresh install)" )
    Config: $ETC/csf.conf   -   Migration report: $ETC/migration-report.txt

    Next:
$( [ "$PLATFORM" = "cpanel" ] && echo "      csf --cpanel-check          # compatibility summary" || echo "      csf --platform              # detected platform: $PLATFORM" )
      csf -l                      # status (is the table loaded?)
      csf health                  # verify enforcement
      csf --selftest              # is CSF (and LFD) really protecting the server?

    LFD (brute-force detection): $LFD_STATE
EOF
if [ "$MODE" != "ENFORCING" ]; then
cat <<EOF
      once enforcing:  systemctl enable --now csf.service lfd.service
EOF
fi
if [ "$MODE" = "ENFORCING" ]; then
cat <<EOF
    The firewall is ENFORCING and was loaded above. Confirm you still have
    access (new SSH session), then you are done. If a reload is ever refused
    for lockout safety, fix TCP_IN/MGMT_PORTS and run: csf -r
EOF
else
cat <<EOF
    TESTING mode: the ruleset was generated + validated but NOT applied.
    When ready: set TESTING="0" in $ETC/csf.conf, confirm TCP_IN/MGMT_PORTS,
    then apply with auto-revert:  csf --safe-reload   ('csf --confirm' to keep)
EOF
fi

# standalone UI: (re)start last, so an update launched from the UI itself is
# finished before the service that spawned it restarts
if [ "${UI_RESTART:-0}" = "1" ]; then
    cat <<EOT

    Standalone web UI (csf2-ui) - listening on 127.0.0.1 only.
      1. create a login:   csf --ui-user add admin     (password + authenticator code)
EOT
    _guide=csf-firewall-no-panel
    if [ -n "${UI_PUBLISHED:-}" ]; then
    _guide=csf-firewall-cloudpanel
    cat <<EOT
      2. sign in at:       $UI_PUBLISHED   (CloudPanel reverse-proxy site)
EOT
    elif [ "$PLATFORM" = "cloudpanel" ]; then
    _guide=csf-firewall-cloudpanel
    cat <<EOT
      2. publish it:       CloudPanel > Add Site > Reverse Proxy > http://127.0.0.1:6789
                           (or reinstall with CSF_UI_DOMAIN=fw.your-host.tld)
         or tunnel it:     ssh -L 6789:127.0.0.1:6789 root@this-server  ->  http://127.0.0.1:6789
EOT
    else
    cat <<EOT
      2. publish it:       behind your web server with HTTPS (nginx/Caddy -> http://127.0.0.1:6789)
         or tunnel it:     ssh -L 6789:127.0.0.1:6789 root@this-server  ->  http://127.0.0.1:6789
EOT
    fi
    cat <<EOT
      Guide: https://docs.underhost.com/article/$_guide/
EOT
    systemctl --no-block restart csf2-ui.service >/dev/null 2>&1 || true
fi
