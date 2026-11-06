package CSF2::Health;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Health - self-health and configuration sanity checks.
#
# check(\%config, $nft, $state) returns an ordered list of check results:
#   { name, status ('ok'|'warn'|'fail'), detail }
# The caller decides how to render/exit. Pure enough to unit-test with a
# dry-run Nft and an injected config.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use CSF2::Ruleset;

sub _r { return { name => $_[0], status => $_[1], detail => $_[2] } }

###############################################################################
# check(\%config, $nft, $state) -> (\@results, $worst)
#   $worst is 'ok' | 'warn' | 'fail'
sub check {
    my ($config, $nft, $state) = @_;
    $config ||= {};
    my @out;

    # nft binary
    if ($nft && $nft->available) {
        push @out, _r('nft binary', 'ok', $nft->{nft});
    } elsif ($nft && $nft->{dry_run}) {
        push @out, _r('nft binary', 'warn', 'dry-run mode (no enforcement)');
    } else {
        push @out, _r('nft binary', 'fail', 'nft not found or not executable');
    }

    # table present. A missing table is only a failure when enforcing; in
    # TESTING mode the ruleset is intentionally generated but not applied.
    if ($nft) {
        my $exists    = $nft->table_exists;
        my $enforcing = $config->{TESTING} ? 0 : 1;
        my $sev = $exists ? 'ok' : ($enforcing ? 'fail' : 'warn');
        my $detail = $exists ? 'loaded'
                   : ($enforcing ? 'NOT loaded while enforcing - run: csf -r'
                                 : 'not loaded (TESTING mode - not enforcing)');
        push @out, _r('table inet csf', $sev, $detail);
    }

    # config: TCP_IN non-empty
    my $tcp_in = $config->{TCP_IN} // q{};
    push @out, _r('TCP_IN', ($tcp_in =~ /\S/ ? 'ok' : 'warn'),
        ($tcp_in =~ /\S/ ? $tcp_in : 'empty - no inbound service ports open'));

    # config: management ports covered by TCP_IN (lockout risk)
    my %open = map { $_ => 1 } split /\s*,\s*/, $tcp_in;
    my @mgmt = grep { length } split /\s*,\s*/, ($config->{MGMT_PORTS} // q{});
    my @missing;
    for my $p (@mgmt) {
        next if $open{$p};
        # range check
        my $covered = 0;
        for my $e (keys %open) { if ($e =~ /^(\d+):(\d+)$/ && $p >= $1 && $p <= $2) { $covered = 1; last } }
        push @missing, $p unless $covered;
    }
    push @out, _r('management ports', (@missing ? 'warn' : 'ok'),
        (@missing ? "not open in TCP_IN: " . join(',', @missing) : 'all covered by TCP_IN'));

    # config: INPUT_POLICY sane
    my $pol = $config->{INPUT_POLICY} // 'drop';
    push @out, _r('input policy', (($pol eq 'drop' || $pol eq 'accept') ? 'ok' : 'fail'), $pol);

    # config: enforcing vs testing
    my $enf = $config->{TESTING} ? 0 : 1;
    push @out, _r('enforcement', ($enf ? 'ok' : 'warn'),
        ($enf ? 'enforcing' : 'TESTING enabled - firewall is not enforcing'));

    # candidate ruleset must at least generate + (if nft) validate
    if ($state) {
        my $script = eval { CSF2::Ruleset::build($config, $state->state_for_ruleset) };
        if (!defined $script) {
            push @out, _r('ruleset build', 'fail', "generation error: $@");
        } else {
            push @out, _r('ruleset build', 'ok', length($script) . ' bytes');
            if ($nft) {
                my ($vok, $vout) = $nft->validate($script);
                push @out, _r('ruleset validate', ($vok ? 'ok' : 'fail'),
                    ($vok ? 'nft -c passed' : $vout));
            }
        }
    }

    # IPv6 posture
    push @out, _r('IPv6', ($config->{IPV6} ? 'ok' : 'warn'),
        ($config->{IPV6} ? 'enabled (first-class)' : 'disabled - IPv6 traffic unfiltered by CSF sets'));

    my $worst = 'ok';
    for my $c (@out) {
        $worst = 'fail' if $c->{status} eq 'fail';
        $worst = 'warn' if $c->{status} eq 'warn' && $worst ne 'fail';
    }
    return (\@out, $worst);
}

1;
