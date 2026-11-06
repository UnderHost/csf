# CSF 2.0 — Roadmap

Shipped (2.0.x testing): native nftables engine, LFD 2.0 (risk scoring +
progressive enforcement), cPanel integration + auto-setup, WAF escalation,
WHM UI (embedded), migration/uninstall of legacy CSF v15, Security Level
presets, Threat Intelligence feeds, self-test, update-from-website.

## Planned modules (future releases)
1. Adaptive Login Protection (LFD successor: SSH/WHM/cPanel/Webmail/FTP/SMTP/IMAP/WP,
   distributed + password-spray detection, ASN/subnet correlation, trusted devices)
2. cPanel-aware WAF (per-domain ModSecurity/OWASP CRS, virtual patching, CMS profiles,
   detection-only mode, one-click per-domain+rule exclusion)
3. Outbound Abuse Guard (outbound spam, per-account SMTP volume, direct-to-MX, port 25
   restriction, phishing/malware/C2 detection, per-account response levels)
4. Account-Level Network Isolation (csf --isolate-user, per-user egress/PHP restriction,
   CageFS/account-ownership integration)
5. WordPress Protection (wp-login/xmlrpc, enumeration, upload scanning, file monitoring,
   vulnerable-plugin detection, temporary virtual patches, per-domain policy)
6. API & Bot Protection (rate limits, credential-stuffing, bad-bot ID, verified crawler
   FCrDNS, JS challenge, per-endpoint limits)
7. Egress Firewall (per-service/per-user outbound policy, dangerous ports, TI-based egress,
   miner/proxy detection, RPZ domain blocking)
8. Behavioral Detection Engine (deterministic baselines/anomalies first; ML later, optional)
9. Vulnerability Intelligence (KEV catalogue, cPanel/OS/service advisories, WP plugin CVEs,
   exposure alerts + safe temporary mitigation)
10. Scanner & Recon Detection (horizontal/vertical/slow scans, service enumeration,
    .env/.git/backup probing, IPv6-distributed scans)
11. Reputation Scoring (feed confidence + local behavior + recurrence + type + age -> action)
12. Honeypot Sensors (decoy SSH/admin/WP paths, feed reputation engine; never a real shell)
13. Firewall Health & Self-Test (extend csf --selftest/--validate/--safe-mode/--rollback)
14. Central Cluster Management (policy distribution, shared attacker intel, signed packages,
    drift detection, incident dashboard, poisoning protection)
15. Temporary Access Manager (csf --grant ssh <ip> --duration 2h, single-use, audit trail)
16. GeoIP & ASN Policy (per-service country/ASN policy, provider/proxy categories, exceptions
    for verified search engines/monitoring)
17. DDoS Mitigation (SYN/UDP/ICMP limits, per-port thresholds, HTTP rate control, auto profiles,
    upstream-provider integration)
18. File Integrity & Malware Events (critical file/cron/SSH-key monitoring, correlate with
    egress, isolate account; ImunifyAV/ClamAV integration)
19. DNS Security (RPZ, malware/phishing domain blocking, tunneling detection, recursion limits)
20. Security Events & Notifications (email/WHM/webhook/Slack/Discord, severity, dedup,
    throttling, daily digest, JSON for SIEM)
21. Abuse Evidence Collector (per-account/domain evidence, JSON/PDF export, privacy-aware retention)
22. Reseller Security Policies (scoped views/actions without root)
23. Security Profiles (Balanced/Shared/WordPress/Mail/High-Security/Dev/API/Lockdown)
24. Extension & Integration Framework (signed plugins, stable event/feed/detection/remediation APIs)

## Priority order for first strong release
nftables engine -> Adaptive Login Protection -> Threat Intelligence ->
Outbound Abuse Guard -> Account Isolation -> Health/Rollback -> WAF -> WordPress ->
Reputation Scoring -> Cluster Management.
Highest commercial value: Threat Intelligence + Outbound Abuse Guard + per-account isolation.
