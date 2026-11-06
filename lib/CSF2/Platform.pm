package CSF2::Platform;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Platform - which hosting platform is this server, and what ports does
# it need open. cPanel keeps its own module (CSF2::Cpanel); this covers the
# servers without WHM: CloudPanel and plain Linux (generic).
#
# The root path is injectable so detection is unit-testable against a fixture
# tree, exactly like CSF2::Cpanel.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use CSF2::Cpanel;

# Port presets per platform => { TCP_IN, UDP_IN, MGMT_PORTS }.
# MGMT_PORTS are the ports the lockout guard refuses to close.
our %PRESETS = (
    cloudpanel => {
        # SSH, HTTP, HTTPS, CloudPanel admin (8443). UDP 443 = HTTP/3 (QUIC).
        TCP_IN     => '22,80,443,8443',
        UDP_IN     => '443',
        MGMT_PORTS => '22,8443',
    },
    generic => {
        TCP_IN     => '22,80,443',
        UDP_IN     => '',
        MGMT_PORTS => '22',
    },
);

sub new {
    my ($class, %opts) = @_;
    my $self = { root => defined $opts{root} ? $opts{root} : '' };
    return bless $self, $class;
}

sub _p { my ($s,$rel) = @_; return $s->{root} . $rel }

###############################################################################
# is_cloudpanel() -> bool
# CloudPanel ships its CLI as /usr/bin/clpctl and keeps its app under
# /home/clp; either marker is enough.
sub is_cloudpanel {
    my ($s) = @_;
    return 1 if -e $s->_p('/usr/bin/clpctl');
    return 1 if -d $s->_p('/home/clp');
    return 0;
}

sub is_directadmin { my $s = shift; return (-d $s->_p('/usr/local/directadmin')) ? 1 : 0 }

###############################################################################
# detect() -> 'cpanel' | 'directadmin' | 'cloudpanel' | 'generic'
sub detect {
    my ($s) = @_;
    return 'cpanel'      if CSF2::Cpanel->new(root => $s->{root})->is_cpanel;
    return 'directadmin' if $s->is_directadmin;
    return 'cloudpanel'  if $s->is_cloudpanel;
    return 'generic';
}

# label($platform) -> human name for the UI / CLI
sub label {
    my ($s, $p) = @_;
    return { cpanel => 'cPanel & WHM', directadmin => 'DirectAdmin',
             cloudpanel => 'CloudPanel', generic => 'Linux (no control panel)' }->{$p} || $p;
}

sub preset { my ($s,$n) = @_; return $PRESETS{$n} ? { %{ $PRESETS{$n} } } : undef }

###############################################################################
# ssh_ports() -> configured SSH ports (default 22)
# Reads sshd_config AND sshd_config.d/*.conf: Debian/Ubuntu put overrides there,
# and a missed custom port would lock the admin out.
sub ssh_ports {
    my ($s) = @_;
    my @files = ($s->_p('/etc/ssh/sshd_config'), sort glob($s->_p('/etc/ssh/sshd_config.d') . '/*.conf'));
    my @ports;
    for my $f (@files) {
        next unless -e $f && open my $fh, '<', $f;
        while (my $l = <$fh>) {
            next if $l =~ /^\s*#/;
            push @ports, $1 if $l =~ /^\s*Port\s+(\d+)/i;
        }
        close $fh;
    }
    @ports = (22) unless @ports;
    my %u; return grep { !$u{$_}++ } @ports;
}

###############################################################################
# recommended_config(%opts) -> \%config_fragment
#   platform  => 'cloudpanel' | 'generic' (default: detect)
#   extra_ssh => port or [ports] (e.g. the live SSH login port)
# Same guarantee as CSF2::Cpanel::recommended_config: every detected SSH port is
# open AND a management port, so a fresh install can never lock the admin out.
sub recommended_config {
    my ($s, %opts) = @_;
    my $plat = $opts{platform} || $s->detect;
    $plat = 'generic' unless $PRESETS{$plat};
    my $preset = $s->preset($plat);
    my @ssh = $s->ssh_ports;
    push @ssh, grep { /^\d+$/ } (ref $opts{extra_ssh} eq 'ARRAY' ? @{$opts{extra_ssh}} : ($opts{extra_ssh} // ()));
    my %tcp  = map { $_ => 1 } grep { length } split /,/, $preset->{TCP_IN};
    my %mgmt = map { $_ => 1 } grep { length } split /,/, $preset->{MGMT_PORTS};
    # the preset's 22 is only a default: drop it when sshd listens elsewhere
    unless (grep { $_ == 22 } @ssh) { delete $tcp{22}; delete $mgmt{22} }
    for my $p (@ssh) { $tcp{$p} = 1; $mgmt{$p} = 1 }
    return {
        platform   => $plat,
        TCP_IN     => join(',', sort { $a <=> $b } keys %tcp),
        UDP_IN     => $preset->{UDP_IN},
        MGMT_PORTS => join(',', sort { $a <=> $b } keys %mgmt),
        ssh_ports  => [ sort { $a <=> $b } keys %{{ map { $_=>1 } @ssh }} ],
    };
}

1;
