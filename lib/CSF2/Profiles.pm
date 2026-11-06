package CSF2::Profiles;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Profiles - one-click security-posture presets.
#
# Each profile is a set of csf.conf values that tune how aggressively the risk
# engine (CSF2::Risk / LFD 2.0) scores and blocks, how long it remembers an
# offender, and whether drops are logged. Profiles deliberately do NOT change
# TCP_IN/ports or TESTING - those are server-specific and changing them could
# lock an admin out. INPUT_POLICY is pinned to "drop" (default-deny) on every
# security profile.
#
# Tuned for 2026/2027 cPanel hosting: SSH/mail/WordPress/WAF brute-force and
# distributed attacks are the dominant threat, so the knobs here are the risk
# thresholds, reputation half-life, offence memory and progressive escalation.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;

# order + metadata for the UI
our @ORDER = qw(low medium high attack);

our %PROFILES = (
    low => {
        label => 'Low',
        tagline => 'Relaxed - fewest false positives',
        desc => 'Blocks only clear, sustained attacks. Best for servers with '
              . 'noisy but legitimate traffic, or where false positives are '
              . 'costly. Reputation is forgiven quickly.',
        config => {
            INPUT_POLICY  => 'drop',
            DROP_LOG      => '0',
            T_MONITOR     => '40',
            T_THROTTLE    => '70',
            T_SHORT_BLOCK => '100',
            T_LONG_BLOCK  => '140',
            T_PERM        => '200',
            HALFLIFE      => '1800',      # 30m - fast decay
            OFFENSE_TTL   => '86400',     # 1 day
            PERM_AFTER    => '8',
        },
    },
    medium => {
        label => 'Medium',
        tagline => 'Balanced - recommended default',
        desc => 'The recommended baseline for most cPanel servers. Catches '
              . 'brute-force and correlated multi-service attacks quickly while '
              . 'keeping false positives low. Reputation decays over hours.',
        config => {
            INPUT_POLICY  => 'drop',
            DROP_LOG      => '0',
            T_MONITOR     => '30',
            T_THROTTLE    => '50',
            T_SHORT_BLOCK => '70',
            T_LONG_BLOCK  => '90',
            T_PERM        => '100',
            HALFLIFE      => '3600',      # 1h
            OFFENSE_TTL   => '604800',    # 7 days
            PERM_AFTER    => '5',
        },
    },
    high => {
        label => 'High',
        tagline => 'Strict - proactive protection',
        desc => 'For hardened / high-value servers. Blocks sooner, remembers '
              . 'offenders far longer, escalates repeat offenders to permanent '
              . 'blocks faster, and logs drops. Slightly higher chance of a '
              . 'false positive on very noisy IPs.',
        config => {
            INPUT_POLICY  => 'drop',
            DROP_LOG      => '1',
            T_MONITOR     => '20',
            T_THROTTLE    => '35',
            T_SHORT_BLOCK => '50',
            T_LONG_BLOCK  => '70',
            T_PERM        => '90',
            HALFLIFE      => '7200',      # 2h - slow decay
            OFFENSE_TTL   => '1209600',   # 14 days
            PERM_AFTER    => '3',
        },
    },
    attack => {
        label => 'Attack mode',
        tagline => 'Lockdown - server under active attack',
        desc => 'Emergency posture for a server under active attack. Blocks on '
              . 'the first strong signal, remembers offenders for weeks, and '
              . 'escalates to a permanent block after just two offences, with '
              . 'full drop logging. Expect some false positives; switch back to '
              . 'Medium/High once the attack subsides.',
        config => {
            INPUT_POLICY  => 'drop',
            DROP_LOG      => '1',
            T_MONITOR     => '15',
            T_THROTTLE    => '25',
            T_SHORT_BLOCK => '35',
            T_LONG_BLOCK  => '50',
            T_PERM        => '65',
            HALFLIFE      => '21600',     # 6h - long memory
            OFFENSE_TTL   => '2592000',   # 30 days
            PERM_AFTER    => '2',
        },
    },
);

# names() -> ordered list of profile ids
sub names { return @ORDER }

# get($name) -> \%profile | undef
sub get { my ($n) = @_; return $PROFILES{$n} }

# config_for($name) -> \%config_keys | undef
sub config_for { my ($n) = @_; return $PROFILES{$n} ? { %{ $PROFILES{$n}{config} } } : undef }

# The full set of keys any profile manages (used to detect the active profile).
sub managed_keys {
    my %k;
    for my $p (values %PROFILES) { $k{$_} = 1 for keys %{ $p->{config} } }
    return sort keys %k;
}

# detect(\%current_config) -> profile id whose values all match, or '' (custom)
sub detect {
    my ($cfg) = @_;
    for my $name (@ORDER) {
        my $pc = $PROFILES{$name}{config};
        my $match = 1;
        for my $k (keys %$pc) {
            my $cur = defined $cfg->{$k} ? "$cfg->{$k}" : '';
            if ($cur ne "$pc->{$k}") { $match = 0; last }
        }
        return $name if $match;
    }
    return '';
}

1;
