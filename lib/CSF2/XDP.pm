package CSF2::XDP;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::XDP - OPTIONAL eBPF/XDP fast-drop layer.
#
# For severe, high-rate attackers, dropping in the XDP hook (in the NIC driver,
# before the kernel network stack) is far cheaper than a normal netfilter drop.
# This layer maintains BPF hash maps of banned IPv4/IPv6 addresses that the XDP
# program consults for an early XDP_DROP.
#
# IMPORTANT: this is strictly OPTIONAL (per the design brief). CSF works fully
# without it; if XDP/bpftool is unavailable every call is a safe no-op and the
# nftables sets remain the source of truth. Only single addresses are pushed
# here - CIDR/interval logic stays in nftables.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use Socket qw(inet_pton AF_INET AF_INET6);
use CSF2::IP qw(checkip normalize);

sub new {
    my ($class, %opts) = @_;
    my $self = {
        enabled  => $opts{enabled} ? 1 : 0,
        dry_run  => $opts{dry_run} ? 1 : 0,
        bpftool  => $opts{bpftool} || _find_bpftool(),
        map4     => $opts{map4} || '/sys/fs/bpf/csf/deny4',   # pinned BPF maps
        map6     => $opts{map6} || '/sys/fs/bpf/csf/deny6',
        iface    => $opts{iface},
        log      => [],
    };
    return bless $self, $class;
}

sub _find_bpftool {
    for my $p (qw(/usr/sbin/bpftool /sbin/bpftool /usr/bin/bpftool)) {
        return $p if -x $p;
    }
    return 'bpftool';
}

sub log { return $_[0]->{log} }

###############################################################################
# available() -> bool
# XDP is usable when enabled AND bpftool exists AND the maps are pinned.
# In dry-run we report available so the wiring/tests can exercise the paths.
sub available {
    my ($self) = @_;
    return 0 unless $self->{enabled};
    return 1 if $self->{dry_run};
    return 0 unless -x $self->{bpftool};
    return 0 unless -e $self->{map4};   # loader must have pinned the maps
    return 1;
}

###############################################################################
# _key_bytes($ip) -> "0xNN 0xNN ..." key for bpftool, or undef
# Packs the address into network-order bytes (4 for v4, 16 for v6).
sub _key_bytes {
    my ($ip) = @_;
    my $fam = checkip($ip) or return (undef, undef);
    my $packed = $fam == 6 ? inet_pton(AF_INET6, $ip) : inet_pton(AF_INET, $ip);
    return (undef, undef) unless defined $packed;
    my $key = join(' ', map { sprintf('0x%02x', ord) } split //, $packed);
    return ($fam, $key);
}

sub _map_for { my ($self, $fam) = @_; return $fam == 6 ? $self->{map6} : $self->{map4} }

sub _run {
    my ($self, @argv) = @_;
    push @{ $self->{log} }, [@argv];
    return 1 if $self->{dry_run};
    # list-form exec, no shell
    my $rc = system(@argv);
    return ($rc == 0) ? 1 : 0;
}

###############################################################################
# drop_add($ip) -> bool   (add an IP to the XDP fast-drop map)
sub drop_add {
    my ($self, $ip) = @_;
    return 0 unless $self->available;
    $ip = normalize($ip) // $ip;
    my ($fam, $key) = _key_bytes($ip);
    return 0 unless $fam;
    my $map = $self->_map_for($fam);
    # value = 1 (present). "any" allows overwrite without error.
    return $self->_run($self->{bpftool}, qw(map update pinned), $map,
                       'key', split(/ /, $key), 'value', '0x01', 'any');
}

# drop_del($ip) -> bool
sub drop_del {
    my ($self, $ip) = @_;
    return 0 unless $self->available;
    $ip = normalize($ip) // $ip;
    my ($fam, $key) = _key_bytes($ip);
    return 0 unless $fam;
    my $map = $self->_map_for($fam);
    return $self->_run($self->{bpftool}, qw(map delete pinned), $map,
                       'key', split(/ /, $key));
}

1;
