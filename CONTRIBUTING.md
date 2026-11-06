# Contributing to CSF

Thank you for helping improve CSF - Core Shield Firewall.

## Reporting a bug

Open an issue with the **Bug report** template. Please include:

- `csf -v`, your operating system and control panel (cPanel, CloudPanel or none);
- the output of `csf --selftest`;
- what you did, what you expected and what happened;
- relevant lines from `/var/lib/csf/lfd.log`, `/var/log/csf2-ui.log` or the
  installer output.

Security problems: see [SECURITY.md](SECURITY.md) - never in a public issue.

## Pull requests

1. Keep changes focused: one fix or feature per pull request.
2. CSF must stay safe to run on production servers. A change must never be able
   to lock the administrator out: management ports, the allow list and
   `csf --safe-reload` (auto-revert) exist for that reason.
3. Add or update tests in `t/` and run the suite:

   ```sh
   sh run-tests.sh
   ```

   The installer refuses to install when a test fails, so every test must pass.
4. Match the style of the surrounding code: plain Perl 5 with core modules only
   (no CPAN dependencies), POSIX `sh` for scripts.
5. Describe in the pull request what you tested and on which system.

## Layout

| Path | What it is |
|---|---|
| `bin/csf2` | the `csf` command (CLI) |
| `bin/lfd2` | LFD 2.0, the login failure daemon |
| `lib/CSF2/` | the engine: nftables, rules, state, detection, risk scoring, Threat Intelligence, scanner, platform detection, UI auth |
| `cpanel/` | the web interface (WHM plugin, also used by the standalone UI) |
| `ui/csf2-ui` | the standalone web interface service (servers without WHM) |
| `etc/` | default configuration |
| `systemd/` | service units |
| `t/` | the test suite |
| `install.sh`, `uninstall.sh` | installer / uninstaller |

By contributing you agree that your contribution is licensed under the
GNU General Public License v3.0 or later, like the rest of the project.
