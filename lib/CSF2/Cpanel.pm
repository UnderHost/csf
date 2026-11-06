package CSF2::Cpanel;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Cpanel - cPanel & WHM awareness: detection, version, service/port
# discovery, cPHulk status, and sensible port presets.
#
# CSF 2.0 is cPanel-first, so this centralises everything cPanel-specific
# instead of scattering /usr/local/cpanel checks through the codebase. The root
# path is injectable so detection is unit-testable against a fixture tree.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;

# Named port presets. Each => { TCP_IN, UDP_IN, MGMT_PORTS }.
# The installer starts from a preset then refines with live service discovery.
our %PRESETS = (
    standard_cpanel => {
        TCP_IN  => '20,21,22,25,26,53,80,110,143,443,465,587,993,995,2077,2078,2079,2080,2082,2083,2086,2087,2095,2096',
        UDP_IN  => '20,21,53',
        MGMT_PORTS => '22,2087,2083,2086,2082',
    },
    web_hosting => {
        TCP_IN  => '22,80,443,2082,2083,2086,2087,2095,2096',
        UDP_IN  => '',
        MGMT_PORTS => '22,2087,2083',
    },
    mail_server => {
        TCP_IN  => '22,25,110,143,443,465,587,993,995,2087,2083',
        UDP_IN  => '',
        MGMT_PORTS => '22,2087,2083',
    },
    dns_only => {
        TCP_IN  => '22,53,953,2087',
        UDP_IN  => '53',
        MGMT_PORTS => '22,2087',
    },
    high_security => {
        TCP_IN  => '22,443,2087',
        UDP_IN  => '',
        MGMT_PORTS => '22,2087',
    },
    custom => {
        TCP_IN  => '',
        UDP_IN  => '',
        MGMT_PORTS => '22',
    },
);

# Well-known cPanel service -> conventional inbound port(s).
our %SERVICE_PORTS = (
    ssh       => ['22'],
    ftp       => ['20','21'],
    smtp      => ['25','26'],
    smtps     => ['465'],
    submission=> ['587'],
    dns       => ['53'],
    http      => ['80'],
    https     => ['443'],
    pop3      => ['110'],
    pop3s     => ['995'],
    imap      => ['143'],
    imaps     => ['993'],
    cpanel    => ['2082','2083'],
    whm       => ['2086','2087'],
    webmail   => ['2095','2096'],
    webdisk   => ['2077','2078'],
);

sub new {
    my ($class, %opts) = @_;
    my $self = { root => defined $opts{root} ? $opts{root} : '' };
    return bless $self, $class;
}

sub _p { my ($s,$rel) = @_; return $s->{root} . $rel }

###############################################################################
# is_cpanel() -> bool
sub is_cpanel { my $s = shift; return (-d $s->_p('/usr/local/cpanel')) ? 1 : 0 }

###############################################################################
# version() -> string | undef   (contents of /usr/local/cpanel/version)
sub version {
    my ($s) = @_;
    my $f = $s->_p('/usr/local/cpanel/version');
    return undef unless -e $f;
    open my $fh, '<', $f or return undef;
    my $v = <$fh>; close $fh;
    $v =~ s/\s+$// if defined $v;
    return $v;
}

###############################################################################
# cphulk_enabled() -> bool
# cPHulk stores an 'enabled' marker under /var/cpanel/hulkd/. CSF respects it:
# it does not duplicate cPHulk's brute-force blocking, it correlates with it.
sub cphulk_enabled {
    my ($s) = @_;
    return 1 if -e $s->_p('/var/cpanel/hulkd/enabled');
    return 0;
}

###############################################################################
# modsec_installed() -> bool  (cPanel EA4 ModSecurity presence)
sub modsec_installed {
    my ($s) = @_;
    return 1 if -e $s->_p('/etc/apache2/conf.d/modsec2.conf');
    return 1 if -e $s->_p('/usr/local/apache/conf/modsec2.conf');
    return 1 if -d $s->_p('/etc/apache2/conf.d/modsec');
    return 0;
}

###############################################################################
# preset($name) -> \%config_fragment | undef
sub preset { my ($s,$n) = @_; return $PRESETS{$n} ? { %{ $PRESETS{$n} } } : undef }
sub preset_names { return sort keys %PRESETS }

###############################################################################
# ports_for_services(\@services) -> sorted unique port list
sub ports_for_services {
    my ($s, $services) = @_;
    my %seen;
    for my $svc (@{ $services || [] }) {
        for my $p (@{ $SERVICE_PORTS{lc $svc} || [] }) { $seen{$p} = 1 }
    }
    return sort { $a <=> $b } keys %seen;
}

###############################################################################
# discover(%opts) -> \%config_fragment
# Build a TCP_IN/UDP_IN recommendation from a preset, optionally narrowed to the
# services actually present. Pass services => [...] (from live detection or a
# fixture) to restrict; otherwise the full preset is returned.
sub discover {
    my ($s, %opts) = @_;
    my $preset = $s->preset($opts{preset} || 'standard_cpanel')
                 or return { TCP_IN => '', UDP_IN => '', MGMT_PORTS => '22' };
    return $preset unless $opts{services};

    my @svc_ports = $s->ports_for_services($opts{services});
    my %keep = map { $_ => 1 } @svc_ports;
    my @tcp = grep { $keep{$_} } split /,/, $preset->{TCP_IN};
    # always retain management ports so discovery can never lock WHM out
    my %mgmt = map { $_ => 1 } split /,/, $preset->{MGMT_PORTS};
    for my $m (keys %mgmt) { push @tcp, $m unless grep { $_ eq $m } @tcp }
    my %u = map { $_ => 1 } @tcp;
    return {
        TCP_IN     => join(',', sort { $a <=> $b } keys %u),
        UDP_IN     => $preset->{UDP_IN},
        MGMT_PORTS => $preset->{MGMT_PORTS},
    };
}

###############################################################################
# ssh_ports() -> list of configured SSH ports (from sshd_config; default 22)
# Critical for lockout safety: if the admin moved SSH off 22, the firewall must
# open the real port. Multiple "Port" lines are all returned.
sub ssh_ports {
    my ($s) = @_;
    my @ports;
    my $f = $s->_p('/etc/ssh/sshd_config');
    if (-e $f && open my $fh, '<', $f) {
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
# Build a cPanel-appropriate TCP_IN/UDP_IN/MGMT_PORTS from a preset, guaranteeing
# the detected SSH port(s) (and any extra_ssh, e.g. the live login port) are
# open and treated as management ports. This is what makes a fresh install
# self-configure on any cPanel server.
sub recommended_config {
    my ($s, %opts) = @_;
    my $preset = $s->preset($opts{preset} || 'standard_cpanel') or return {};
    my @ssh = $s->ssh_ports;
    push @ssh, grep { /^\d+$/ } (ref $opts{extra_ssh} eq 'ARRAY' ? @{$opts{extra_ssh}} : ($opts{extra_ssh} // ()));
    my %tcp  = map { $_ => 1 } grep { length } split /,/, $preset->{TCP_IN};
    my %mgmt = map { $_ => 1 } grep { length } split /,/, $preset->{MGMT_PORTS};
    for my $p (@ssh) { $tcp{$p} = 1; $mgmt{$p} = 1 }
    return {
        TCP_IN     => join(',', sort { $a <=> $b } keys %tcp),
        UDP_IN     => $preset->{UDP_IN},
        MGMT_PORTS => join(',', sort { $a <=> $b } keys %mgmt),
        ssh_ports  => [ sort { $a <=> $b } keys %{{ map { $_=>1 } @ssh }} ],
    };
}

###############################################################################
# summary() -> \%facts  (for `csf --cpanel-check` and the WHM dashboard)
sub summary {
    my ($s) = @_;
    return {
        cpanel        => $s->is_cpanel,
        version       => $s->version,
        cphulk        => $s->cphulk_enabled,
        modsecurity   => $s->modsec_installed,
    };
}

1;
