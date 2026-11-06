package CSF2::Ruleset;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Ruleset - builds the native nftables ruleset "table inet csf".
#
# One inet table serves IPv4 and IPv6. Blocked/allowed addresses live in named
# sets so a single IP can be added/removed at runtime with `nft add element`
# WITHOUT rebuilding the ruleset. Temporary bans use native set timeouts, so
# they expire in-kernel with no userspace sweep.
#
# build(\%config, \%state) returns the full nft script as a string. It is a
# pure function (no I/O), which makes it directly testable and lets the caller
# validate the candidate ruleset before applying it atomically.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
# Next-generation fork of ConfigServer Security & Firewall (C) 2006-2025
# Jonathan Michaelson.
###############################################################################

use strict;
use warnings;
use CSF2::IP qw(parse);

our $TABLE = 'inet csf';

# The full set inventory. name => (type, flags)
our @SETS = (
    [ 'csf_allow4',  'ipv4_addr', 'interval'        ],
    [ 'csf_allow6',  'ipv6_addr', 'interval'        ],
    [ 'csf_tallow4', 'ipv4_addr', 'timeout'         ],
    [ 'csf_tallow6', 'ipv6_addr', 'timeout'         ],
    [ 'csf_deny4',   'ipv4_addr', 'interval'        ],
    [ 'csf_deny6',   'ipv6_addr', 'interval'        ],
    [ 'csf_temp4',   'ipv4_addr', 'timeout'         ],
    [ 'csf_temp6',   'ipv6_addr', 'timeout'         ],
    # High-volume categories fed by the correlation engine / reputation feeds.
    [ 'csf_abuse4',  'ipv4_addr', 'interval'        ],
    [ 'csf_abuse6',  'ipv6_addr', 'interval'        ],
    # Threat-intelligence feed sets (populated by CSF2::ThreatIntel).
    [ 'csf_ti_high4',      'ipv4_addr', 'interval'  ],
    [ 'csf_ti_high6',      'ipv6_addr', 'interval'  ],
    [ 'csf_ti_botnet4',    'ipv4_addr', 'interval'  ],
    [ 'csf_ti_botnet6',    'ipv6_addr', 'interval'  ],
    [ 'csf_ti_attackers4', 'ipv4_addr', 'interval'  ],
    [ 'csf_ti_attackers6', 'ipv6_addr', 'interval'  ],
);

###############################################################################
# helpers
sub _csv {
    my ($v) = @_;
    return () unless defined $v && $v ne q{};
    my @p = grep { length } map { s/^\s+|\s+$//gr } split /,/, $v;
    return @p;
}

# Render "elements = { a, b, c }" for inline set population, or empty string.
sub _elements {
    my ($list) = @_;
    return q{} unless $list && @$list;
    return "\t\telements = { " . join(', ', @$list) . " }\n";
}

# Inject admin custom rules (string or arrayref of nft lines) at a chain hook.
# Blank lines are skipped; each line is indented
# to sit inside the chain block. Admin rules therefore survive regeneration.
sub _push_include {
    my ($out, $inc) = @_;
    return unless defined $inc;
    my @lines = ref($inc) eq 'ARRAY' ? @$inc : split /\n/, $inc;
    for my $l (@lines) {
        $l =~ s/\s+$//;
        next if $l eq q{};
        push @$out, "\t\t$l";
    }
    return;
}

# Render a timeout set's inline elements: "ip timeout 3600s"
sub _timeout_elements {
    my ($list) = @_;
    return q{} unless $list && @$list;
    my @e = map { "$_->{ip} timeout $_->{timeout}s" } @$list;
    return "\t\telements = { " . join(', ', @e) . " }\n";
}

###############################################################################
# build(\%config, \%state) -> nft script string
#
# %config keys (all optional, sensible defaults):
#   TCP_IN, UDP_IN     - comma lists of inbound ports (both families, inet)
#   TCP_OUT, UDP_OUT   - comma lists of outbound ports (empty => allow all out)
#   IPV6               - 1 to emit IPv6 rules (default 1)
#   ICMP_IN            - 1 to accept inbound ICMP echo (default 1)
#   DROP_LOG           - 1 to log dropped inbound packets (default 0)
#   INPUT_POLICY       - 'drop' (default) or 'accept'
#
# %state keys (all optional arrayrefs of canonical strings unless noted):
#   allow4, allow6, deny4, deny6, abuse4, abuse6
#   temp   - arrayref of { ip, family(4|6), kind('deny'|'allow'), timeout(sec) }
sub build {
    my ($config, $state) = @_;
    $config ||= {};
    $state  ||= {};

    my $ipv6      = exists $config->{IPV6}    ? $config->{IPV6}    : 1;
    my $icmp_in   = exists $config->{ICMP_IN} ? $config->{ICMP_IN} : 1;
    my $drop_log  = $config->{DROP_LOG} ? 1 : 0;
    my $policy    = ($config->{INPUT_POLICY} && $config->{INPUT_POLICY} eq 'accept')
                    ? 'accept' : 'drop';

    my @tcp_in  = _csv($config->{TCP_IN});
    my @udp_in  = _csv($config->{UDP_IN});
    my @tcp_out = _csv($config->{TCP_OUT});
    my @udp_out = _csv($config->{UDP_OUT});

    # Partition temp entries into deny/allow per family.
    my (@t_deny4, @t_deny6, @t_allow4, @t_allow6);
    for my $e (@{ $state->{temp} || [] }) {
        my $kind = $e->{kind} || 'deny';
        my $fam  = $e->{family} || 4;
        my $row  = { ip => $e->{ip}, timeout => ($e->{timeout} || 3600) };
        if ($kind eq 'allow') { $fam == 6 ? push(@t_allow6,$row) : push(@t_allow4,$row) }
        else                  { $fam == 6 ? push(@t_deny6,$row)  : push(@t_deny4,$row)  }
    }

    my %inline = (
        csf_allow4  => _elements($state->{allow4}),
        csf_allow6  => _elements($state->{allow6}),
        csf_deny4   => _elements($state->{deny4}),
        csf_deny6   => _elements($state->{deny6}),
        csf_abuse4  => _elements($state->{abuse4}),
        csf_abuse6  => _elements($state->{abuse6}),
        csf_temp4   => _timeout_elements(\@t_deny4),
        csf_temp6   => _timeout_elements(\@t_deny6),
        csf_tallow4 => _timeout_elements(\@t_allow4),
        csf_tallow6 => _timeout_elements(\@t_allow6),
    );

    my @out;
    push @out, "#!/usr/sbin/nft -f";
    push @out, "# CSF 2.0 nftables ruleset - table $TABLE";
    push @out, "# Generated by CSF2::Ruleset. Do not edit by hand; use csf commands.";
    push @out, "";
    # Atomic replace: delete-if-exists then recreate in one transaction.
    push @out, "table $TABLE {}";
    push @out, "delete table $TABLE";
    push @out, "";
    push @out, "table $TABLE {";

    # --- sets ---
    for my $s (@SETS) {
        my ($name, $type, $flags) = @$s;
        next if $type eq 'ipv6_addr' && !$ipv6;
        push @out, "\tset $name {";
        push @out, "\t\ttype $type";
        push @out, "\t\tflags $flags" if $flags;
        my $el = $inline{$name} || q{};
        chomp(my $elt = $el);
        push @out, $elt if $elt ne q{};
        push @out, "\t}";
    }
    push @out, "";

    # --- input chain ---
    push @out, "\tchain input {";
    push @out, "\t\ttype filter hook input priority 0; policy $policy;";
    push @out, "\t\tiif \"lo\" accept";
    push @out, "\t\tct state established,related accept";
    push @out, "\t\tct state invalid drop";

    # allow (permanent + temporary) before any deny
    push @out, "\t\tip saddr \@csf_allow4 accept";
    push @out, "\t\tip saddr \@csf_tallow4 accept";
    if ($ipv6) {
        push @out, "\t\tip6 saddr \@csf_allow6 accept";
        push @out, "\t\tip6 saddr \@csf_tallow6 accept";
    }

    # deny (temporary, permanent, abuse)
    my $dl = $drop_log ? "log prefix \"csf-drop-in: \" " : q{};
    push @out, "\t\tip saddr \@csf_temp4 ${dl}drop";
    push @out, "\t\tip saddr \@csf_deny4 ${dl}drop";
    push @out, "\t\tip saddr \@csf_abuse4 ${dl}drop";
    if ($ipv6) {
        push @out, "\t\tip6 saddr \@csf_temp6 ${dl}drop";
        push @out, "\t\tip6 saddr \@csf_deny6 ${dl}drop";
        push @out, "\t\tip6 saddr \@csf_abuse6 ${dl}drop";
    }

    # threat-intelligence inbound blocking (high + botnet + attackers).
    if ($config->{TI_ENABLE}) {
        my $tl = $drop_log ? "log prefix \"csf-ti-in: \" " : q{};
        push @out, "\t\tip saddr \@csf_ti_high4 ${tl}drop";
        push @out, "\t\tip saddr \@csf_ti_botnet4 ${tl}drop";
        push @out, "\t\tip saddr \@csf_ti_attackers4 ${tl}drop";
        if ($ipv6) {
            push @out, "\t\tip6 saddr \@csf_ti_high6 ${tl}drop";
            push @out, "\t\tip6 saddr \@csf_ti_botnet6 ${tl}drop";
            push @out, "\t\tip6 saddr \@csf_ti_attackers6 ${tl}drop";
        }
    }

    # ICMP: allow echo (v4) and essential ICMPv6 (ND/PMTUD) so IPv6 keeps working.
    if ($icmp_in) {
        push @out, "\t\tip protocol icmp icmp type { echo-request } accept";
    }
    if ($ipv6) {
        # ND + diagnostics are required for a functional IPv6 stack.
        push @out, "\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-router-solicit, echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept";
    }

    # service ports (inet => both families)
    if (@tcp_in) {
        push @out, "\t\ttcp dport { " . join(', ', @tcp_in) . " } ct state new accept";
    }
    if (@udp_in) {
        push @out, "\t\tudp dport { " . join(', ', @udp_in) . " } accept";
    }

    # custom include hook (admin rules survive regeneration)
    _push_include(\@out, $config->{INCLUDE_INPUT});
    push @out, "\t\t# csf_include_input";

    if ($policy eq 'drop') {
        my $fdl = $drop_log ? "log prefix \"csf-drop-in-policy: \" " : q{};
        push @out, "\t\tcounter ${fdl}comment \"csf-input-drop\"";
    }
    push @out, "\t}";
    push @out, "";

    # --- output chain ---
    push @out, "\tchain output {";
    push @out, "\t\ttype filter hook output priority 0; policy accept;";
    push @out, "\t\toif \"lo\" accept";
    # threat-intel outbound blocking BEFORE the established-accept, so even an
    # already-open connection to a botnet C2 / hijacked network is severed.
    if ($config->{TI_ENABLE}) {
        my $tl = $drop_log ? "log prefix \"csf-ti-out: \" " : q{};
        push @out, "\t\tip daddr \@csf_ti_high4 ${tl}drop";
        push @out, "\t\tip daddr \@csf_ti_botnet4 ${tl}drop";
        if ($ipv6) {
            push @out, "\t\tip6 daddr \@csf_ti_high6 ${tl}drop";
            push @out, "\t\tip6 daddr \@csf_ti_botnet6 ${tl}drop";
        }
    }
    push @out, "\t\tct state established,related accept";
    if (@tcp_out || @udp_out) {
        # Restrictive outbound: only listed ports leave as NEW.
        push @out, "\t\ttcp dport { " . join(', ', @tcp_out) . " } ct state new accept" if @tcp_out;
        push @out, "\t\tudp dport { " . join(', ', @udp_out) . " } accept" if @udp_out;
        _push_include(\@out, $config->{INCLUDE_OUTPUT});
        push @out, "\t\t# csf_include_output";
        push @out, "\t\tct state new drop";
    } else {
        _push_include(\@out, $config->{INCLUDE_OUTPUT});
        push @out, "\t\t# csf_include_output";
    }
    push @out, "\t}";
    push @out, "}";
    push @out, "";

    return join("\n", @out);
}

# The canonical ordered list of set names for a given ipv6 setting.
sub set_names {
    my ($ipv6) = @_;
    $ipv6 = 1 unless defined $ipv6;
    return map { $_->[0] } grep { $ipv6 || $_->[1] ne 'ipv6_addr' } @SETS;
}

1;
