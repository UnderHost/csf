package CSF2::Lockout;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Lockout - management lockout protection.
#
# Before an enforcing (policy drop) ruleset is applied, verify that the
# administrator's own connection will survive it:
#   * the live SSH client IP is not in a deny/temp set;
#   * the SSH port and configured management ports are actually open in TCP_IN,
#     OR the admin IP is explicitly allowed.
# Critical risks BLOCK the apply (unless forced); softer risks are warnings.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use CSF2::IP qw(ip_in_any normalize);

###############################################################################
# ssh_info() -> ($client_ip, $server_port)  (either may be undef)
# Read from SSH_CONNECTION ("cip cport sip sport"), falling back to SSH_CLIENT.
sub ssh_info {
    my %env = @_ ? @_ : %ENV;   # allow injection for testing
    if (defined $env{SSH_CONNECTION} && $env{SSH_CONNECTION} =~ /\S/) {
        my @f = split /\s+/, $env{SSH_CONNECTION};
        return ($f[0], $f[3]);
    }
    if (defined $env{SSH_CLIENT} && $env{SSH_CLIENT} =~ /\S/) {
        my @f = split /\s+/, $env{SSH_CLIENT};
        return ($f[0], $f[2]);
    }
    return (undef, undef);
}

###############################################################################
# guard(\%config, \%state, %opts) -> \%result
#   %config : { TCP_IN, MGMT_PORTS, INPUT_POLICY, ... }
#   %state  : { allow4, allow6, deny4, deny6, temp[...] }  (from State)
#   %opts   : env => \%fake_env (testing), force => 1
#
# Result: { ok => bool, blocks => [..], warnings => [..], ssh_ip => .., ssh_port => .. }
sub guard {
    my ($config, $state, %opts) = @_;
    $config ||= {}; $state ||= {};
    my (@blocks, @warnings);

    my ($cip, $sport) = $opts{env} ? ssh_info(%{ $opts{env} }) : ssh_info();
    my $policy = ($config->{INPUT_POLICY} && $config->{INPUT_POLICY} eq 'accept')
                 ? 'accept' : 'drop';

    # A policy-accept firewall cannot lock anyone out by default.
    if ($policy ne 'drop') {
        return { ok => 1, blocks => [], warnings => [], ssh_ip => $cip, ssh_port => $sport };
    }

    my %tcp_in = map { $_ => 1 } _csv($config->{TCP_IN});
    my @mgmt   = _csv($config->{MGMT_PORTS});
    push @mgmt, $sport if defined $sport && $sport =~ /^\d+$/;

    # 1) management ports must be open, or admins on them get dropped.
    my %seen;
    for my $p (@mgmt) {
        next if $seen{$p}++;
        next if $tcp_in{$p} || _port_in_ranges($p, [keys %tcp_in]);
        push @warnings, "management port $p is not open in TCP_IN; connections to it will be dropped";
    }

    # 2) the live SSH client IP must not be blocked.
    my @deny = (@{ $state->{deny4} || [] }, @{ $state->{deny6} || [] });
    my @allow = (@{ $state->{allow4} || [] }, @{ $state->{allow6} || [] });
    my @tempdeny = map { $_->{ip} } grep { ($_->{kind}||'deny') eq 'deny' } @{ $state->{temp} || [] };

    if (defined $cip && normalize($cip)) {
        if (my $hit = ip_in_any($cip, [@deny, @tempdeny])) {
            push @blocks, "your SSH client IP $cip is in a deny/temp set ($hit); applying would drop your session";
        }
        my $allowed  = ip_in_any($cip, \@allow) ? 1 : 0;
        my $port_ok  = (defined $sport && ($tcp_in{$sport} || _port_in_ranges($sport, [keys %tcp_in]))) ? 1 : 0;
        if (!$allowed && !$port_ok) {
            push @blocks, "your SSH connection ($cip".(defined $sport ? " on port $sport" : q{}).
                ") would be dropped: neither the port is open in TCP_IN nor your IP is allowed";
        }
    } else {
        push @warnings, "could not determine the SSH client IP (SSH_CONNECTION unset); lockout check is limited - run with care or from console";
    }

    my $ok = (!@blocks || $opts{force}) ? 1 : 0;
    push @warnings, "lockout guard OVERRIDDEN by force; ".scalar(@blocks)." critical risk(s) ignored"
        if @blocks && $opts{force};

    return { ok => $ok, blocks => \@blocks, warnings => \@warnings, ssh_ip => $cip, ssh_port => $sport };
}

###############################################################################
# helpers
sub _csv {
    my ($v) = @_;
    return () unless defined $v && $v ne q{};
    return grep { length } map { s/^\s+|\s+$//gr } split /,/, $v;
}

# _port_in_ranges($port, \@entries) - handle "1000:2000" range entries in TCP_IN
sub _port_in_ranges {
    my ($port, $entries) = @_;
    return 0 unless defined $port && $port =~ /^\d+$/;
    for my $e (@$entries) {
        if ($e =~ /^(\d+):(\d+)$/) {
            return 1 if $port >= $1 && $port <= $2;
        }
    }
    return 0;
}

1;
