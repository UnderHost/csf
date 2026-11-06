package CSF2::Cloudflare;
###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Cloudflare - manage Cloudflare edge IP ranges on the allow list.
#
# When a site sits behind Cloudflare, all visitor traffic arrives from
# Cloudflare's edge network. Allowlisting those ranges keeps LFD from ever
# blocking a shared Cloudflare address (which would take down every proxied
# site at once) while your origin still drops direct-to-IP abuse.
#
# Ranges are published by Cloudflare at:
#   https://www.cloudflare.com/ips-v4
#   https://www.cloudflare.com/ips-v6
# and are added to the normal csf.allow list tagged "Cloudflare" so they show
# up in the Allow List tab and can be removed cleanly.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################
use strict;
use warnings;

our $TAG = 'Cloudflare';
our @ENDPOINTS = (
    'https://www.cloudflare.com/ips-v4',
    'https://www.cloudflare.com/ips-v6',
);

# A pinned fallback used only when the network fetch fails, so enabling the
# integration still works on a locked-down box. Kept intentionally small; the
# live fetch is authoritative and supersedes this.
our @FALLBACK = qw(
    173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22
    141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20
    197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
    104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
    2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32
    2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32
);

sub _curl {
    my ($u) = @_;
    $u =~ s{[^A-Za-z0-9:/._?=&-]}{}g;   # sanitise
    my $c = (-x '/usr/bin/curl') ? '/usr/bin/curl' : 'curl';
    my $out = `$c -fsSL --max-time 15 "$u" 2>/dev/null`;
    return defined $out ? $out : '';
}

# fetch() -> list of CIDR strings (live if possible, else the pinned fallback)
# CSF2_CF_OFFLINE=1 forces the pinned fallback (used by tests so the install
# gate never depends on outbound network reachability).
sub fetch {
    return @FALLBACK if $ENV{CSF2_CF_OFFLINE};
    my (@v4, @v6);
    for my $u (@ENDPOINTS) {
        my $body = _curl($u);
        for my $l (split /\r?\n/, $body) {
            $l =~ s/\s+//g;
            next unless $l =~ m{^[0-9A-Fa-f:.]+/\d{1,3}$};
            if ($l =~ /:/) { push @v6, $l } else { push @v4, $l }
        }
    }
    # if a whole family was unreachable/blocked, backfill it from the pinned list
    push @v4, grep { $_ !~ /:/ } @FALLBACK unless @v4;
    push @v6, grep { $_ =~ /:/ } @FALLBACK unless @v6;
    my @ips = (@v4, @v6);
    return @ips if @ips >= 5;   # sanity: a real response has ~22 ranges
    return @FALLBACK;
}

# enable(eng => $engine) -> (ok, message, count)
sub enable {
    my (%a) = @_;
    my $eng = $a{eng} or return (0, 'internal: engine required', 0);
    my @ips = fetch();
    return (0, 'could not obtain Cloudflare IP ranges', 0) unless @ips;
    my $n = 0;
    for my $ip (@ips) {
        my ($ok) = $eng->allow($ip, $TAG);
        $n++ if $ok;
    }
    return (1, "$n Cloudflare ranges on the allow list", $n);
}

# disable(eng => $engine, state => $state) -> (ok, message, count)
sub disable {
    my (%a) = @_;
    my ($eng, $state) = @a{qw/eng state/};
    return (0, 'internal: engine/state required', 0) unless $eng && $state;
    my $allow = $state->load_list('allow');
    my $n = 0;
    for my $e (@$allow) {
        next unless defined $e->{comment} && $e->{comment} =~ /\bCloudflare\b/i;
        my ($ok) = $eng->unallow($e->{canonical});
        $n++ if $ok;
    }
    return (1, "removed $n Cloudflare ranges from the allow list", $n);
}

# count_active($state) -> number of Cloudflare-tagged allow entries
sub count_active {
    my ($state) = @_;
    return 0 unless $state;
    my $allow = $state->load_list('allow');
    return scalar grep { defined $_->{comment} && $_->{comment} =~ /\bCloudflare\b/i } @$allow;
}

1;
