# Security policy

CSF is a firewall, so we treat security reports as our highest priority.

## Supported versions

| Version | Supported |
|---|---|
| 2.3.x | Yes - current stable |
| 2.2.0 release candidates | No - update to 2.3.x |
| 2.1.x and older | No - update to 2.3.x (`csf --self-update`) |

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security problem.**

E-mail **support@underhost.com** with the subject **"CSF security report"** and include:

- the CSF version (`csf -v`) and the operating system / control panel;
- what an attacker can do, and the steps to reproduce it;
- any proof-of-concept, logs or patch you have.

We confirm receipt within 2 business days, keep you informed while we work on a
fix, and credit you in the changelog when the fix is released, unless you prefer
to stay anonymous. Please give us a reasonable time to release a fix before
publishing details.

## Scope

In scope: the firewall engine, LFD, the WHM plugin, the standalone web interface
(`csf2-ui`: sign-in, two-factor authentication, sessions, CSRF), the installer and
updater, Threat Intelligence and the malware scanner.

Out of scope: problems in ClamAV, YARA, nftables, cPanel, CloudPanel or the
operating system themselves - please report those upstream.
