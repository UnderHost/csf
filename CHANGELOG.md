# Changelog

All notable changes to CSF - Core Shield Firewall. Dates are release dates (UTC).

## 2.3.1 - 2026-11-06 · Never lock out the administrator

- **The installer allows your SSH address.** Like legacy ConfigServer CSF, the IP of the SSH session running `install.sh` is added to the allow list, also under `sudo`. Updates run from cron or the web interface have no SSH session and skip this.
- **The malware scanner never blocks a trusted uploader:** an IP on the allow list, in `csf.ignore`, or an administrator who signed in to the web interface. The file is still quarantined. On servers without a panel the interface shares the web server log with the sites, so an administrator signing in at the moment of an upload could be taken for the uploader.
- `csf --scan-setup` runs the first scan right away instead of waiting for the 5-minute schedule.

## 2.3.0 - 2026-11-06 · Core Shield Firewall, stable for every platform

- **New name:** CSF is now **Core Shield Firewall** (formerly cPanel Shield Firewall), one code base for cPanel, CloudPanel and servers with no control panel, with a new full logo.
- **Important - the firewall now comes back after a reboot.** The `csf.service` unit had an ordering cycle, so systemd silently skipped it at boot: a rebooted 2.1.x / 2.2.x server ran with no CSF rules and no LFD until restarted. Update every 2.x server.
- **Longer LFD blocks really last longer.** Repeat attackers are escalated, but nftables kept the first, short timeout, so the IP was free again after 5 minutes. Each IP now has one entry and the longer block is applied in the kernel; a shorter request never shortens a block.
- **LFD never blocks the server's own addresses.** The list of local IPs was always empty.
- **New: malicious upload scanning** - ClamAV + rfxn signatures and YARA every 5 minutes, quarantine, uploader blocking, e-mail alerts and the **Malware Scan** tab. See [Malicious upload scanning](https://shield.underhost.com/firewall/docs/#malware).
- **New: LFD reads the systemd journal** when there is no `/var/log/auth.log` or `/var/log/secure` (Debian 12 / 13), so SSH brute force is detected there too (`LF_JOURNAL`). `csf --selftest` now fails when LFD has no source for SSH failures.
- **CloudPanel and no panel are stable** (they were the 2.2 release candidate), tested on 10 Linux distributions with a reboot and a real SSH brute-force attack on each.
- **Installer:** installs missing Perl modules and nftables (minimal images), restores SELinux labels (AlmaLinux / CloudLinux 8: the units were invisible to systemd), warns when firewalld is active, and shows the real version and the next steps for your platform. Scanner set-up waits for the package lock, enables EPEL on CloudLinux and works with YARA 4.1.

## 2.1.6 - 2026-11-06 · Important: LFD really runs

- **LFD now starts after an install or update.** The installer (and therefore every update, which re-runs it) only enabled `lfd.service` for the next boot without starting it, so a server installed or updated since its last reboot was not banning brute-force attackers. When the firewall is enforcing, the installer now enables and (re)starts LFD - an update also loads the new LFD code - and prints whether LFD is running.
- **`csf --selftest` catches it.** A stopped LFD on an enforcing firewall is now a **FAIL** with the fix command (it was only a warning, and an old `lfd.log` made the detection check pass). `csf.service` is judged together with the loaded ruleset.
- **Update now** from the WHM **Update** tab or with `csf --self-update`, then run `csf --selftest`.

## 2.2.0 RC2 - 2026-11-06 · Release candidate: CloudPanel & no control panel

- **Runs beyond cPanel.** Detects cPanel, CloudPanel or a plain Linux server (`csf --platform`) and applies the right port preset on a fresh install (`csf --platform-setup cloudpanel|generic`), reading `sshd_config.d` for the SSH port.
- **Standalone web interface (`csf2-ui`)** for servers without WHM: the same firewall UI on 127.0.0.1:6789 with login, TOTP two-factor authentication, CSRF protection, sessions and per-IP lockout; accounts via `csf --ui-user`. Failed sign-ins are logged for LFD.
- **CloudPanel:** `CSF_UI_DOMAIN=fw.example.com sh install.sh` publishes the UI as an HTTPS reverse-proxy site.
- The firewall CGI now refuses to run outside WHM unless the standalone UI launched it. Migration drops the unused legacy `UI_*` settings.
- Includes the 2.1.6 LFD start and self-test fixes (RC2; RC1 was built 2026-11-05).
- Superseded by **2.3.0** stable.

## 2.1.5 - 2026-08-26 · Critical: Threat Intel hang fix

- **Fixed a hang in Threat Intelligence updates.** Large feed sets were fed to `nft` over a stdin pipe, which could deadlock once the script exceeded the OS pipe buffer - leaving `csf --ti-update` and its `nft -f` child stuck at 0% CPU. The hourly cron then stacked a new hung pair every hour until the server ran out of resources. nft is now fed via a temporary file (no pipe, no deadlock).
- `csf --ti-update` now takes a **single-instance lock** (a second run skips instead of stacking) and a hard **5-minute timeout** so a run can never live forever.

## 2.1.4 - 2026-08-26 · Update-tab fix

- Fixed a reload loop on the WHM **Update** tab: progress is followed with AJAX polling, and the page reloads only **once** when an update genuinely completes - never on a stale progress value from a previous run.

## 2.1.3 - 2026-08-26 · UI & update polish

- Firewall **operation log** is now a readable light panel (it was low-contrast under WHM's default styling).
- Cleaner Cloudflare cloud mark on the Firewall tab.
- The update check is **cache-busted** so an intermediate CDN or a stale local cache can no longer report an old "latest release"; a cached manifest behind the installed version is discarded, and the cache is cleared after an update.

## 2.1.2 - 2026-08-26 · Update reliability

- Fixed the WHM / `csf --self-update` updater on hardened servers: the installer now runs via `sh` and extracts under `/var/lib/csf`, so updates work even when `/tmp` is mounted `noexec`.
- In-place upgrades replace the module tree cleanly (no more nested `CSF2/CSF2` path).
- Cloudflare fetch backfills a blocked IPv4 or IPv6 endpoint from the pinned list; the test suite no longer depends on outbound network.
- Cleaner WHM module footer.

## 2.1.1 - 2026-08-26 · Firewall control & Cloudflare

- Redesigned **Firewall** tab: Start / Stop / Restart controls with a live operation log, status badges, and an open-ports view (TCP/UDP in & out).
- One-click **Cloudflare** edge allowlist - adds all Cloudflare IP ranges to the allow list (`csf --cf-enable` / `--cf-disable` / `--cf-update`).
- Redesigned **Diagnostics** tab: status cards plus an "Administrator tests" panel that runs the self-test in place.
- Compatibility: AlmaLinux / CloudLinux / RHEL / Rocky 8, 9, 10 supported; Ubuntu 22.04 / 24.04 (beta).

## 2.1.0 - 2026-08-26 · First stable GA

- First stable general-availability release.
- New WHM **Update** tab: one-click in-place update with SHA-256 verification and a live progress bar.
- New `csf --self-update` CLI command.
- Update-available indicator in the interface.
- Full-logo WHM header and "Powered by UnderHost" attribution.
- Real ON/OFF (green/red) toggle switches for Threat Intelligence feeds.
- Full documentation site and stable release framing.

## 2.0.x - pre-release testing

- Threat Intelligence feed manager with dedicated nftables sets and category policies.
- Branded installer, Security Level presets, extensive WHM configuration editor.
- Embedded WHM interface, cPanel auto port detection, `csf --selftest`.
- Native nftables engine, LFD 2.0 risk scoring, legacy CSF v15 migration/uninstall.
