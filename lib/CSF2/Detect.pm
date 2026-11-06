package CSF2::Detect;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Detect - modular detection: turn a raw log line into normalised
# security events. Each rule is independent and data-driven, so new services
# are added by appending a rule, not by editing one enormous parser.
#
# A normalised event:
#   { source_ip, dest_port, service, event, username, severity, metadata }
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
# Detection concepts derive from ConfigServer Security & Firewall (GPLv3).
###############################################################################

use strict;
use warnings;
use CSF2::IP qw(checkip normalize);

###############################################################################
# Built-in rule set. Each rule:
#   service  - logical source (sshd, exim, dovecot, ftpd, cpanel, ...)
#   event    - normalised event name
#   severity - base risk contribution (tunable via Risk engine)
#   port     - conventional destination port (metadata / correlation hint)
#   re       - regex with a named (?<ip>...) capture; optional (?<user>...)
#
# Patterns follow the same log shapes CSF has matched for years, ported to
# named captures. IPs are validated + canonicalised before an event is emitted.
our @RULES = (
    # --- SSH ---
    { service=>'sshd', event=>'auth_failure', severity=>10, port=>22,
      re => qr/Failed password for (?:invalid user )?(?<user>[^\s]+) from (?<ip>[0-9a-fA-F:.]+)(?: port \d+)?/ },
    { service=>'sshd', event=>'invalid_user', severity=>12, port=>22,
      re => qr/Invalid user (?<user>[^\s]+) from (?<ip>[0-9a-fA-F:.]+)/ },
    { service=>'sshd', event=>'auth_failure', severity=>10, port=>22,
      re => qr/authentication failure;.*rhost=(?<ip>[0-9a-fA-F:.]+)/ },
    { service=>'sshd', event=>'probe', severity=>5, port=>22,
      re => qr/Did not receive identification string from (?<ip>[0-9a-fA-F:.]+)/ },
    { service=>'sshd', event=>'bad_protocol', severity=>6, port=>22,
      re => qr/(?:banner exchange|Bad protocol version identification).* from (?<ip>[0-9a-fA-F:.]+)/ },

    # --- Exim / SMTP AUTH ---
    { service=>'exim', event=>'smtp_auth_failure', severity=>10, port=>587,
      re => qr/(?:authenticator failed|535 Incorrect authentication data) for .*\[(?<ip>[0-9a-fA-F:.]+)\]/ },
    { service=>'exim', event=>'smtp_auth_failure', severity=>10, port=>465,
      re => qr/dovecot_login authenticator failed for .*\[(?<ip>[0-9a-fA-F:.]+)\]/ },

    # --- Dovecot (POP3/IMAP) ---
    { service=>'dovecot', event=>'mail_login_failure', severity=>8, port=>993,
      re => qr/(?:pop3|imap)-login: (?:Info: )?(?:Aborted login|Disconnected|Login aborted)[^\n]*rip=(?<ip>[0-9a-fA-F:.]+)/ },
    { service=>'dovecot', event=>'mail_login_failure', severity=>8, port=>995,
      re => qr/auth failed[^\n]*rip=(?<ip>[0-9a-fA-F:.]+)/ },

    # --- FTP (pure-ftpd / proftpd) ---
    { service=>'ftpd', event=>'ftp_auth_failure', severity=>10, port=>21,
      re => qr/pure-ftpd:.*\[WARNING\] Authentication failed for user.*\n?.*\[(?<ip>[0-9a-fA-F:.]+)\]/ },
    { service=>'ftpd', event=>'ftp_auth_failure', severity=>10, port=>21,
      re => qr/\(\?@(?<ip>[0-9a-fA-F:.]+)\).*\[WARNING\] Authentication failed/ },
    { service=>'ftpd', event=>'ftp_auth_failure', severity=>10, port=>21,
      re => qr/proftpd.*USER .*no such user found from \S+ \[(?<ip>[0-9a-fA-F:.]+)\]/ },

    # --- cPanel / WHM / Webmail login failures ---
    { service=>'cpanel', event=>'panel_login_failure', severity=>15, port=>2083,
      re => qr/FAILED LOGIN.*(?:from|host)[=:\s]+(?<ip>[0-9a-fA-F:.]+)/ },
    { service=>'cpanel', event=>'panel_login_failure', severity=>15, port=>2087,
      re => qr/cpsrvd.*\bfailed\b.*\bip\b[=:\s]+(?<ip>[0-9a-fA-F:.]+)/i },

    # --- CSF standalone web UI (csf2-ui, /var/log/csf2-ui.log) ---
    { service=>'csf2-ui', event=>'panel_login_failure', severity=>15, port=>443,
      re => qr/csf2-ui: login failed for user (?<user>\S+) from (?<ip>[0-9a-fA-F:.]+)/ },

    # --- WordPress (webserver access log driven; opt-in) ---
    { service=>'wordpress', event=>'wp_login_probe', severity=>6, port=>443,
      re => qr/(?<ip>[0-9a-fA-F:.]+) .*"POST [^"]*\/wp-login\.php/ },
    { service=>'wordpress', event=>'xmlrpc_abuse', severity=>8, port=>443,
      re => qr/(?<ip>[0-9a-fA-F:.]+) .*"POST [^"]*\/xmlrpc\.php/ },

    # --- ModSecurity / OWASP CRS (WAF -> firewall escalation) ---
    # Severity is derived from the CRS rule id so a single RCE probe scores far
    # higher than a generic anomaly. classify() sets event + severity per hit.
    { service=>'modsecurity', event=>'waf_attack', severity=>0, port=>443,
      re => qr/\[client (?<ip>[0-9a-fA-F:.]+)\][^\n]*ModSecurity[^\n]*\[id "(?<id>\d+)"\]/,
      classify => \&_classify_modsec },
);

###############################################################################
# OWASP CRS rule-id families -> (category, severity, confidence).
# High-confidence exploit classes (RCE, SQLi, path traversal) score high enough
# that a few hits cross the block threshold; generic anomalies stay low so a
# single false positive never fires a network block on its own.
our %CRS_FAMILY = (
    930 => ['path_traversal', 45, 'high'],
    931 => ['rfi',            50, 'high'],
    932 => ['rce',            70, 'high'],
    933 => ['php_injection',  60, 'high'],
    934 => ['ssrf_nodejs',    55, 'high'],
    941 => ['xss',            35, 'med'],
    942 => ['sqli',           45, 'high'],
    943 => ['session_fixation',30,'med'],
    944 => ['java_exploit',   65, 'high'],
    913 => ['scanner',        25, 'med'],
    920 => ['protocol',       10, 'low'],
    921 => ['protocol',       15, 'low'],
);

# _classify_modsec(%captures) -> ($event, $severity, \%metadata)
sub _classify_modsec {
    my %cap = @_;
    my $id  = $cap{id} // 0;
    my $fam = int($id / 1000);
    my $info = $CRS_FAMILY{$fam} || ['anomaly', 8, 'low'];
    my ($cat, $sev, $conf) = @$info;
    return ("waf_$cat", $sev, { rule_id => $id, category => $cat, confidence => $conf });
}

# waf_category($rule_id) -> (category, severity, confidence)  (for the WHM UI)
sub waf_category {
    my ($id) = @_;
    my $info = $CRS_FAMILY{ int(($id||0) / 1000) } || ['anomaly', 8, 'low'];
    return @$info;
}

###############################################################################
# new(%opts)
#   rules => arrayref to replace the default rule set (else built-ins)
sub new {
    my ($class, %opts) = @_;
    my $self = { rules => $opts{rules} || [ @RULES ] };
    return bless $self, $class;
}

# add_rule(\%rule) - extend the rule set at runtime (custom detectors)
sub add_rule { my ($self, $rule) = @_; push @{ $self->{rules} }, $rule; return }

###############################################################################
# scan($line) -> list of normalised event hashrefs (possibly empty)
# A single line may match multiple rules; each match that yields a valid public
# IP becomes an event.
sub scan {
    my ($self, $line) = @_;
    return () unless defined $line;
    my @events;
    for my $rule (@{ $self->{rules} }) {
        if ($line =~ $rule->{re}) {
            my $ip = $+{ip};
            next unless defined $ip;
            $ip = _clean_ip($ip);
            next unless defined $ip;
            my $event    = $rule->{event};
            my $severity = $rule->{severity};
            my $meta     = {};
            # rules may compute event/severity/metadata from their captures
            # (e.g. ModSecurity severity derived from the CRS rule id).
            if ($rule->{classify}) {
                my ($e2, $s2, $m2) = $rule->{classify}->(%+);
                $event    = $e2 if defined $e2;
                $severity = $s2 if defined $s2;
                $meta     = $m2 if ref $m2 eq 'HASH';
            }
            push @events, {
                source_ip => $ip,
                dest_port => $rule->{port},
                service   => $rule->{service},
                event     => $event,
                username  => (defined $+{user} ? $+{user} : undef),
                severity  => $severity,
                metadata  => $meta,
            };
        }
    }
    return @events;
}

###############################################################################
# _clean_ip($raw) -> canonical IP | undef
# Strips a trailing :port on IPv4, surrounding brackets, and validates.
sub _clean_ip {
    my ($raw) = @_;
    return undef unless defined $raw;
    $raw =~ s/^\[|\]$//g;
    # IPv4 with :port (but never touch IPv6, which contains many colons)
    if ($raw =~ /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/) { $raw = $1 }
    return undef unless checkip($raw);
    return normalize($raw);
}

1;
