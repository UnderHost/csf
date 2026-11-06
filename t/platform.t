use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use CSF2::Platform;

sub touch { my $f = shift; open my $fh, '>', $f or die "$f: $!"; print {$fh} @_; close $fh }

# --- detection ---
my $bare = tempdir(CLEANUP => 1);
is(CSF2::Platform->new(root => $bare)->detect, 'generic', 'bare tree is generic');

my $clp = tempdir(CLEANUP => 1);
make_path("$clp/usr/bin"); touch("$clp/usr/bin/clpctl", '');
is(CSF2::Platform->new(root => $clp)->detect, 'cloudpanel', 'clpctl marks CloudPanel');

my $clp2 = tempdir(CLEANUP => 1);
make_path("$clp2/home/clp");
is(CSF2::Platform->new(root => $clp2)->detect, 'cloudpanel', '/home/clp marks CloudPanel');

my $cp = tempdir(CLEANUP => 1);
make_path("$cp/usr/local/cpanel", "$cp/home/clp");
is(CSF2::Platform->new(root => $cp)->detect, 'cpanel', 'cPanel wins over other markers');

my $da = tempdir(CLEANUP => 1);
make_path("$da/usr/local/directadmin");
is(CSF2::Platform->new(root => $da)->detect, 'directadmin', 'DirectAdmin detected');

is(CSF2::Platform->new->label('cloudpanel'), 'CloudPanel', 'label');

# --- CloudPanel ports, default SSH ---
my $r = CSF2::Platform->new(root => $clp)->recommended_config;
is($r->{platform}, 'cloudpanel', 'recommended platform');
is($r->{TCP_IN}, '22,80,443,8443', 'CloudPanel TCP_IN');
is($r->{UDP_IN}, '443', 'CloudPanel UDP_IN (HTTP/3)');
is($r->{MGMT_PORTS}, '22,8443', 'CloudPanel MGMT_PORTS keep SSH + admin');

# --- custom SSH port in sshd_config.d replaces 22 ---
make_path("$clp/etc/ssh/sshd_config.d");
touch("$clp/etc/ssh/sshd_config", "# Port 22\nInclude /etc/ssh/sshd_config.d/*.conf\n");
touch("$clp/etc/ssh/sshd_config.d/10-port.conf", "Port 2222\n");
$r = CSF2::Platform->new(root => $clp)->recommended_config;
is($r->{TCP_IN}, '80,443,2222,8443', 'custom SSH port opened, default 22 dropped');
is($r->{MGMT_PORTS}, '2222,8443', 'custom SSH port is a management port');
is_deeply($r->{ssh_ports}, [2222], 'ssh_ports from sshd_config.d');

# --- live login port is always kept (lockout safety) ---
$r = CSF2::Platform->new(root => $clp)->recommended_config(extra_ssh => 22);
like($r->{TCP_IN}, qr/\b22\b/, 'live SSH port 22 kept open');
like($r->{MGMT_PORTS}, qr/\b2222\b/, 'configured port still kept');

# --- generic preset and unknown platform fallback ---
$r = CSF2::Platform->new(root => $bare)->recommended_config;
is($r->{TCP_IN}, '22,80,443', 'generic TCP_IN');
is($r->{MGMT_PORTS}, '22', 'generic MGMT_PORTS');
$r = CSF2::Platform->new(root => $bare)->recommended_config(platform => 'nonsense');
is($r->{platform}, 'generic', 'unknown platform falls back to generic');

done_testing();
