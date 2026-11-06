use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use CSF2::Cpanel;

# --- detection against a fixture tree ---
my $root = tempdir(CLEANUP => 1);
make_path("$root/usr/local/cpanel");
make_path("$root/var/cpanel/hulkd");
open my $vf, '>', "$root/usr/local/cpanel/version"; print {$vf} "11.136.0.5\n"; close $vf;

my $cp = CSF2::Cpanel->new(root => $root);
ok($cp->is_cpanel, 'detects cPanel from fixture');
is($cp->version, '11.136.0.5', 'reads cPanel version');
ok(!$cp->cphulk_enabled, 'cPHulk not enabled (no marker yet)');
open my $hf, '>', "$root/var/cpanel/hulkd/enabled"; close $hf;
ok($cp->cphulk_enabled, 'cPHulk enabled once marker present');
ok(!$cp->modsec_installed, 'modsec not present in fixture');

# --- a non-cPanel root ---
my $bare = tempdir(CLEANUP => 1);
my $nc = CSF2::Cpanel->new(root => $bare);
ok(!$nc->is_cpanel, 'no cPanel on bare tree');
is($nc->version, undef, 'no version on bare tree');

# --- presets ---
my $std = $cp->preset('standard_cpanel');
like($std->{TCP_IN}, qr/\b2087\b/, 'standard preset opens WHM 2087');
like($std->{TCP_IN}, qr/\b22\b/, 'standard preset opens SSH');
is($cp->preset('does_not_exist'), undef, 'unknown preset undef');
my @pnames = $cp->preset_names;
ok(@pnames >= 5, 'several presets available');

my $mail = $cp->preset('mail_server');
like($mail->{TCP_IN}, qr/\b993\b/, 'mail preset has IMAPS');
unlike($mail->{TCP_IN}, qr/\b80\b/, 'mail preset omits HTTP');

my $hs = $cp->preset('high_security');
is($hs->{TCP_IN}, '22,443,2087', 'high security minimal ports');

# --- service -> ports ---
is_deeply([$cp->ports_for_services(['ssh','https','whm'])], [22,443,2086,2087],
          'ports_for_services maps + sorts');

# --- discovery narrows preset to present services but keeps mgmt ports ---
my $disc = $cp->discover(preset => 'standard_cpanel', services => ['ssh','http','https']);
like($disc->{TCP_IN}, qr/\b80\b/, 'discovery keeps http');
like($disc->{TCP_IN}, qr/\b443\b/, 'discovery keeps https');
like($disc->{TCP_IN}, qr/\b2087\b/, 'discovery still keeps WHM mgmt port (no lockout)');
unlike($disc->{TCP_IN}, qr/\b25\b/, 'discovery drops unused SMTP');

# discovery with no services => full preset
my $full = $cp->discover(preset => 'web_hosting');
is($full->{TCP_IN}, $cp->preset('web_hosting')->{TCP_IN}, 'no services => full preset');

# --- summary ---
my $sum = $cp->summary;
ok($sum->{cpanel}, 'summary cpanel true');
is($sum->{version}, '11.136.0.5', 'summary version');
ok($sum->{cphulk}, 'summary cphulk true');

# --- ssh_ports detection ---
{
    make_path("$root/etc/ssh");
    open my $sc, '>', "$root/etc/ssh/sshd_config";
    print {$sc} "# comment\nPort 22\nPort 2222\n#Port 9999\n";
    close $sc;
    my @sp = $cp->ssh_ports;
    is_deeply([sort {$a<=>$b} @sp], [22,2222], 'ssh_ports reads all Port lines, ignores comments');
}
{
    my $bare2 = tempdir(CLEANUP => 1);
    my $nc2 = CSF2::Cpanel->new(root => $bare2);
    is_deeply([$nc2->ssh_ports], [22], 'ssh_ports defaults to 22 when no sshd_config');
}

# --- recommended_config guarantees SSH + mgmt ports ---
{
    my $rec = $cp->recommended_config(extra_ssh => 2233);
    like($rec->{TCP_IN}, qr/\b2222\b/, 'recommended TCP_IN includes detected SSH port');
    like($rec->{TCP_IN}, qr/\b2233\b/, 'recommended TCP_IN includes live SSH port');
    like($rec->{TCP_IN}, qr/\b2087\b/, 'recommended TCP_IN keeps WHM port');
    like($rec->{MGMT_PORTS}, qr/\b2222\b/, 'SSH port is a management port');
    like($rec->{MGMT_PORTS}, qr/\b2233\b/, 'live SSH port is a management port');
    ok((grep { $_ == 2222 } @{$rec->{ssh_ports}}), 'ssh_ports list returned');
}

done_testing();
