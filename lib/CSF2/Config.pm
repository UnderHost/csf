package CSF2::Config;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Config - configuration loader.
#
# Reads legacy-compatible `KEY = "value"` files (csf.conf) so existing
# installs upgrade in place, layered over CSF 2.0 defaults. A CONFIG_VERSION
# marks the schema for migration.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);

our $CONFIG_VERSION = '2.0';

# CSF 2.0 defaults. Ports mirror a standard cPanel server; the installer
# refines them from live service discovery.
our %DEFAULTS = (
    CONFIG_VERSION => $CONFIG_VERSION,
    TESTING        => 1,          # safe default: do not enforce until reviewed
    IPV6           => 1,
    ICMP_IN        => 1,
    INPUT_POLICY   => 'drop',
    DROP_LOG       => 0,

    TCP_IN  => '20,21,22,25,53,80,110,143,443,465,587,993,995,2077,2078,2079,2080,2082,2083,2086,2087,2095,2096',
    TCP_OUT => '',                # empty => allow all outbound
    UDP_IN  => '53',
    UDP_OUT => '',

    NFT            => '/usr/sbin/nft',
    ETC_DIR        => '/etc/csf',
    VAR_DIR        => '/var/lib/csf',

    # Lockout protection: ports that must remain reachable before an enforcing
    # ruleset is applied. Comma list; the current SSH port is added at runtime.
    MGMT_PORTS     => '22,2087,2083,2086,2082',
    SAFE_RELOAD_TIMEOUT => 30,    # seconds before auto-rollback if unconfirmed

    # LFD also reads auth/mail entries from the systemd journal: auto = only
    # when there is no /var/log/auth.log or /var/log/secure (Debian 12+).
    LF_JOURNAL     => 'auto',

    # Threat Intelligence: download reputation feeds into dedicated nftables
    # sets. Master switch; individual feeds toggle via TI_<FEEDID> = 0|1.
    TI_ENABLE      => 0,

    # Malicious upload scanning (CSF2::Scanner). Off until `csf --scan-setup`.
    SCAN_ENABLE          => 0,
    SCAN_ACTION          => 'quarantine',   # quarantine | alert
    SCAN_BLOCK_UPLOADER  => 1,
    SCAN_BLOCK_TTL       => 86400,
    SCAN_ATTRIB_WINDOW   => 120,
    SCAN_MAX_SIZE        => 5242880,
    SCAN_MAX_FILES       => 20000,
    SCAN_PATHS           => '',
    SCAN_EXCLUDE         => '',
    SCAN_EXT             => '',
    SCAN_CLAMAV_OFFICIAL => 0,
    SCAN_FORCE           => 0,
    SCAN_ALERT_TO        => '',             # empty: LF_ALERT_TO, else root; "none" = no email
);

###############################################################################
# loadconfig(%opts)
#   file => path to csf.conf (default /etc/csf/csf.conf)
# Returns a blessed config object; missing file => defaults only.
sub loadconfig {
    my ($class, %opts) = @_;
    $class = 'CSF2::Config' unless $class && $class ne 'loadconfig';
    my $file = $opts{file} || ($DEFAULTS{ETC_DIR} . '/csf.conf');
    my %cfg = %DEFAULTS;
    my @warnings;

    if (-e $file) {
        sysopen(my $fh, $file, O_RDONLY) or push @warnings, "cannot read $file: $!";
        if ($fh) {
            flock($fh, LOCK_SH);
            while (my $line = <$fh>) {
                chomp $line;
                next if $line =~ /^\s*#/ || $line =~ /^\s*$/;
                # KEY = "value"  or  KEY = value
                if ($line =~ /^\s*([A-Z0-9_]+)\s*=\s*"?(.*?)"?\s*$/) {
                    $cfg{$1} = $2;
                }
            }
            close $fh;
        }
    }

    my $self = { config => \%cfg, warnings => \@warnings, file => $file };
    return bless $self, $class;
}

sub config   { my $s = shift; return %{ $s->{config} } }
sub get       { my ($s,$k,$d) = @_; return exists $s->{config}{$k} ? $s->{config}{$k} : $d }
sub warnings  { my $s = shift; return @{ $s->{warnings} } }

# ports_list($key) -> array of ports from a comma list
sub ports_list {
    my ($s, $key) = @_;
    my $v = $s->get($key, q{});
    return grep { length } map { s/^\s+|\s+$//gr } split /,/, $v;
}

# is_enforcing() -> true when the firewall should actually drop (TESTING off)
sub is_enforcing { my $s = shift; return $s->get('TESTING', 1) ? 0 : 1 }

###############################################################################
# save_keys($file, \%kv) -> (ok, message)
# Update or append `KEY = "value"` lines for the given keys, preserving every
# other line and comment. Only keys matching [A-Z0-9_]+ and values without
# newlines are accepted (defence against injection into the config file).
# Writes atomically (temp + rename) so the live config is never half-written.
sub save_keys {
    my ($class, $file, $kv) = @_;
    return (0, 'no file') unless defined $file;
    my @lines;
    if (open my $in, '<', $file) { @lines = <$in>; close $in; }
    my %want = %$kv;
    for my $k (keys %want) {
        return (0, "invalid key: $k") unless $k =~ /^[A-Z0-9_]+$/;
        $want{$k} = '' unless defined $want{$k};
        $want{$k} =~ s/[\r\n]//g;   # never allow newlines into the config
    }
    my %done;
    for my $l (@lines) {
        if ($l =~ /^\s*([A-Z0-9_]+)\s*=/) {
            my $k = $1;
            if (exists $want{$k} && !$done{$k}) {
                $l = qq{$k = "$want{$k}"\n};
                $done{$k} = 1;
            }
        }
    }
    for my $k (sort keys %want) {
        push @lines, qq{$k = "$want{$k}"\n} unless $done{$k};
    }
    my $tmp = "$file.tmp.$$";
    open my $out, '>', $tmp or return (0, "open $tmp: $!");
    print {$out} @lines;
    close $out;
    rename($tmp, $file) or do { unlink $tmp; return (0, "rename failed: $!") };
    return (1, 'saved');
}

1;
