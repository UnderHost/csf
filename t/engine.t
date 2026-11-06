use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use CSF2::Config;
use CSF2::State;
use CSF2::Nft;
use CSF2::Engine;

my $dir = tempdir(CLEANUP => 1);
mkdir "$dir/etc"; mkdir "$dir/var";

# minimal csf.conf: enforcing drop policy, SSH open
open my $cf, '>', "$dir/etc/csf.conf" or die $!;
print {$cf} <<'CONF';
CONFIG_VERSION = "2.0"
TESTING = "0"
IPV6 = "1"
INPUT_POLICY = "drop"
TCP_IN = "22,80,443"
UDP_IN = "53"
MGMT_PORTS = "22"
CONF
close $cf;

# admin is connected from 203.0.113.5 on port 22 -> guard should pass
$ENV{SSH_CONNECTION} = '203.0.113.5 54321 10.0.0.1 22';

my $config = CSF2::Config->loadconfig(file => "$dir/etc/csf.conf");
my $state  = CSF2::State->new(etc => "$dir/etc", var => "$dir/var");
my $nft    = CSF2::Nft->new(dry_run => 1, nft => '/usr/sbin/nft');
my $eng    = CSF2::Engine->new(config => $config, state => $state, nft => $nft);

sub last_argv { my $l = $nft->log; return $l->[-1] ? join(' ', @{$l->[-1]}) : q{} }

# --- deny (incremental) ---
my ($ok, $msg) = $eng->deny('185.203.44.19', 'SSH brute force');
ok($ok, "deny ok: $msg");
is(last_argv(), '/usr/sbin/nft add element inet csf csf_deny4 { 185.203.44.19 }',
   'deny pushes one element to csf_deny4 (no rebuild)');
ok($state->in_list('deny', '185.203.44.19'), 'deny persisted to state');

# deny v6 goes to csf_deny6
$eng->deny('2001:db8::bad');
is(last_argv(), '/usr/sbin/nft add element inet csf csf_deny6 { 2001:db8::bad }', 'v6 deny -> csf_deny6');

# --- can't deny an allowed IP ---
$eng->allow('9.9.9.9', 'dns');
my ($dok, $dmsg) = $eng->deny('9.9.9.9');
ok(!$dok, "deny refused for allowed IP: $dmsg");

# --- tempdeny with native timeout ---
($ok, $msg) = $eng->tempdeny('10.0.0.9', 1800, comment => 'lfd');
ok($ok, "tempdeny ok: $msg");
is(last_argv(), '/usr/sbin/nft add element inet csf csf_temp4 { 10.0.0.9 timeout 1800s }',
   'tempdeny uses timeout set element');

# tempallow -> tallow set
$eng->tempdeny('10.0.0.20', 600, kind => 'allow');
is(last_argv(), '/usr/sbin/nft add element inet csf csf_tallow4 { 10.0.0.20 timeout 600s }',
   'tempallow -> csf_tallow4');

# --- temprm removes from both temp sets ---
($ok, $msg) = $eng->temprm('10.0.0.9');
ok($ok, "temprm ok: $msg");

# --- inspect ---
my $i = $eng->inspect('185.203.44.19');
is($i->{state}, 'blocked', 'inspect: blocked');
ok((grep { /deny list/ } @{$i->{where}}), 'inspect: found in deny list');
my $i2 = $eng->inspect('9.9.9.9');
is($i2->{state}, 'allowed', 'inspect: allowed');

# --- reload dry_run: builds, guards, validates, does NOT apply ---
my $r = $eng->reload(dry_run => 1);
ok($r->{ok}, 'reload dry_run ok');
ok($r->{guard}{ok}, 'lockout guard passed (SSH IP + port safe)');
ok($r->{validated}, 'ruleset validated');
is($r->{applied}, 0, 'dry_run did not apply');
like($r->{script}, qr/185\.203\.44\.19/, 'generated ruleset contains denied IP inline');
like($r->{script}, qr/tcp dport \{ 22, 80, 443 \}/, 'generated ruleset opens configured ports');

# --- reload that WOULD lock out the admin is refused ---
# Move admin onto a denied IP and close SSH.
$ENV{SSH_CONNECTION} = '185.203.44.19 40000 10.0.0.1 22';
my $r2 = $eng->reload();
ok(!$r2->{ok}, 'reload refused: would lock out admin');
like($r2->{error}, qr/lockout guard refused/, 'error names lockout guard');
ok((grep { /deny\/temp set/ } @{$r2->{guard}{blocks}}), 'guard block explains why');

# --- force overrides ---
my $r3 = $eng->reload(force => 1);
ok($r3->{ok}, 'reload force overrides lockout (dry nft applies cleanly)');

# --- reload honors TESTING: validate-only, no apply ---
{
    my $tdir = tempdir(CLEANUP => 1); mkdir "$tdir/etc"; mkdir "$tdir/var";
    open my $tc, '>', "$tdir/etc/csf.conf";
    print {$tc} "TESTING=\"1\"\nINPUT_POLICY=\"drop\"\nTCP_IN=\"22\"\nMGMT_PORTS=\"22\"\n"; close $tc;
    local $ENV{SSH_CONNECTION} = '203.0.113.5 5 10.0.0.1 22';
    my $tcfg  = CSF2::Config->loadconfig(file => "$tdir/etc/csf.conf");
    my $tst   = CSF2::State->new(etc => "$tdir/etc", var => "$tdir/var");
    my $tnft  = CSF2::Nft->new(dry_run => 1, nft => '/usr/sbin/nft');
    my $teng  = CSF2::Engine->new(config => $tcfg, state => $tst, nft => $tnft);
    my $tr = $teng->reload();
    ok($tr->{ok}, 'TESTING reload ok');
    is($tr->{applied}, 0, 'TESTING reload validates but does NOT apply');
    ok($tr->{testing}, 'testing flag set');
    ok($tr->{validated}, 'ruleset still validated in TESTING');
    my $trf = $teng->reload(force => 1);
    ok($trf->{applied}, 'force applies even in TESTING mode');
}

done_testing();
