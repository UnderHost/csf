package CSF2::IP;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::IP - IPv4/IPv6 parsing, validation, canonical normalization and CIDR.
#
# First-class IPv4 + IPv6. Every address is stored in exactly one canonical
# representation so the same host can never appear twice under two spellings
# (e.g. 2001:db8::1 vs 2001:0db8:0000::0001).
#
# Copyright (C) 2026 CSF - Core Shield Firewall
# Next-generation fork of ConfigServer Security & Firewall (C) 2006-2025
# Jonathan Michaelson. Distributed under the GNU GPL v3.
###############################################################################

use strict;
use warnings;
use Socket qw(inet_pton inet_ntop AF_INET AF_INET6);
use Exporter qw(import);

our @EXPORT_OK = qw(
    checkip family normalize is_ip is_cidr checkcidr parse
    nft_family set_suffix split_ip_spec ip_in_cidr ip_in_any
);

###############################################################################
# checkip($str) -> 4 | 6 | 0
# Returns the IP family for a plain (non-CIDR) address, or 0 if it is not a
# syntactically valid IPv4/IPv6 address.
sub checkip {
    my ($ip) = @_;
    return 0 unless defined $ip;
    $ip =~ s/^\s+|\s+$//g;
    return 0 if $ip eq q{};
    # Reject anything with a prefix here; use checkcidr() for CIDR.
    return 0 if index($ip, '/') >= 0;
    if ($ip =~ /:/) {
        return defined(inet_pton(AF_INET6, $ip)) ? 6 : 0;
    }
    # Require dotted-quad shape with NO leading-zero octets. Leading zeros are
    # ambiguous (octal vs decimal) and a classic IP-parser-confusion security
    # issue; glibc inet_pton rejects them while some libc (e.g. cygwin) do not,
    # so we gate here to guarantee identical, safe behaviour on every platform.
    return 0 unless $ip =~ /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/;
    return defined(inet_pton(AF_INET, $ip)) ? 4 : 0;
}

###############################################################################
# family($str) -> 4 | 6 | 0  (accepts plain IP or CIDR)
sub family {
    my ($str) = @_;
    return 0 unless defined $str;
    my ($addr) = split m{/}, $str, 2;
    return checkip($addr);
}

###############################################################################
# normalize($str) -> canonical string | undef
# Canonicalises a plain address: IPv6 is compressed and lower-cased, IPv4 has
# leading zeros stripped. Returns undef for invalid input.
sub normalize {
    my ($ip) = @_;
    my $fam = checkip($ip);
    return undef unless $fam;
    $ip =~ s/^\s+|\s+$//g;
    if ($fam == 6) {
        return lc inet_ntop(AF_INET6, inet_pton(AF_INET6, $ip));
    }
    return inet_ntop(AF_INET, inet_pton(AF_INET, $ip));
}

###############################################################################
# checkcidr($str) -> (family, canonical_cidr) | (0)
# Validates a CIDR block, canonicalising the address portion. The prefix is
# range-checked (0-32 for v4, 0-128 for v6). Host bits are preserved as given
# (nftables interval sets accept them); only the address spelling is canonical.
sub checkcidr {
    my ($str) = @_;
    return 0 unless defined $str;
    $str =~ s/^\s+|\s+$//g;
    my ($addr, $prefix, $extra) = split m{/}, $str, 3;
    return 0 if defined $extra;                 # more than one slash
    return 0 unless defined $prefix && $prefix =~ /^\d{1,3}$/;
    my $fam = checkip($addr);
    return 0 unless $fam;
    my $max = $fam == 6 ? 128 : 32;
    return 0 if $prefix > $max;
    my $canon = normalize($addr);
    return ($fam, "$canon/$prefix");
}

###############################################################################
# is_ip($str)   -> bool  (plain address only)
# is_cidr($str) -> bool  (CIDR only)
sub is_ip   { return checkip($_[0]) ? 1 : 0 }
sub is_cidr { my @r = checkcidr($_[0]); return $r[0] ? 1 : 0 }

###############################################################################
# parse($str) -> hashref | undef
# Unified parse for a plain IP or a CIDR block. Returns:
#   { type => 4|6, kind => 'ip'|'cidr', family => 'ip'|'ip6',
#     addr => <canonical address>, prefix => <n|undef>,
#     canonical => <canonical ip or cidr>, set => <4|6 suffix> }
sub parse {
    my ($str) = @_;
    return undef unless defined $str;
    $str =~ s/^\s+|\s+$//g;
    if (index($str, '/') >= 0) {
        my ($fam, $canon) = checkcidr($str);
        return undef unless $fam;
        my ($addr, $prefix) = split m{/}, $canon, 2;
        return {
            type => $fam, kind => 'cidr', family => nft_family($fam),
            addr => $addr, prefix => $prefix, canonical => $canon,
            set => set_suffix($fam),
        };
    }
    my $fam = checkip($str);
    return undef unless $fam;
    my $canon = normalize($str);
    return {
        type => $fam, kind => 'ip', family => nft_family($fam),
        addr => $canon, prefix => undef, canonical => $canon,
        set => set_suffix($fam),
    };
}

###############################################################################
# nft_family(4|6) -> 'ip' | 'ip6'   (the nftables L3 keyword)
sub nft_family { return $_[0] && $_[0] == 6 ? 'ip6' : 'ip' }

###############################################################################
# set_suffix(4|6) -> '4' | '6'   (CSF set-name suffix, e.g. csf_deny4)
sub set_suffix { return $_[0] && $_[0] == 6 ? '6' : '4' }

###############################################################################
# ip_in_cidr($ip, $cidr) -> bool
# True if the plain address $ip falls within $cidr (same family). Works for
# IPv4 and IPv6 by masking the packed byte strings, so it is exact for both.
sub ip_in_cidr {
    my ($ip, $cidr) = @_;
    my $ipfam = checkip($ip);
    return 0 unless $ipfam;
    my ($cfam, $canon) = checkcidr($cidr);
    return 0 unless $cfam;
    return 0 unless $ipfam == $cfam;
    my ($net, $prefix) = split m{/}, $canon, 2;
    my $af   = $ipfam == 6 ? AF_INET6 : AF_INET;
    my $pip  = inet_pton($af, $ip);
    my $pnet = inet_pton($af, $net);
    return 0 unless defined $pip && defined $pnet;

    my $full = int($prefix / 8);          # whole bytes to compare
    my $rem  = $prefix % 8;               # leftover bits in the next byte
    return 0 if $full && substr($pip, 0, $full) ne substr($pnet, 0, $full);
    if ($rem) {
        my $mask = (0xFF << (8 - $rem)) & 0xFF;
        my $a = ord(substr($pip,  $full, 1));
        my $b = ord(substr($pnet, $full, 1));
        return 0 if ($a & $mask) != ($b & $mask);
    }
    return 1;
}

###############################################################################
# ip_in_any($ip, \@list) -> matching entry | undef
# Returns the first list entry (plain IP or CIDR) that contains/equals $ip.
sub ip_in_any {
    my ($ip, $list) = @_;
    my $canon = normalize($ip);
    return undef unless defined $canon;
    for my $entry (@{ $list || [] }) {
        if (index($entry, '/') >= 0) {
            return $entry if ip_in_cidr($ip, $entry);
        } else {
            my $n = normalize($entry);
            return $entry if defined $n && $n eq $canon;
        }
    }
    return undef;
}

###############################################################################
# split_ip_spec($str) -> ($ip, $rest)
# Splits a CLI argument such as "1.2.3.4 -p 22 do not block" into the leading
# IP/CIDR token and the remaining descriptive/option text.
sub split_ip_spec {
    my ($str) = @_;
    return (undef, q{}) unless defined $str;
    $str =~ s/^\s+//;
    my ($first, $rest) = split /\s+/, $str, 2;
    $rest = q{} unless defined $rest;
    return ($first, $rest);
}

1;
