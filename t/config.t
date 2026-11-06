use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use CSF2::Config;

my $dir = tempdir(CLEANUP => 1);
my $f = "$dir/csf.conf";
open my $fh, '>', $f; print {$fh} <<'CONF'; close $fh;
# Testing flag
TESTING = "1"
IPV6 = "1"
TCP_IN = "22,80,443"
# a comment
LF_SSHD = "5"
CONF

# --- save_keys updates existing, preserves comments, adds new ---
my ($ok, $m) = CSF2::Config->save_keys($f, { TESTING => '0', TCP_IN => '22,443', T_PERM => '100' });
ok($ok, "save_keys ok: $m");

my $c = CSF2::Config->loadconfig(file => $f);
is($c->get('TESTING'), '0', 'existing key updated');
is($c->get('TCP_IN'), '22,443', 'value with commas updated');
is($c->get('IPV6'), '1', 'untouched key preserved');
is($c->get('LF_SSHD'), '5', 'other key preserved');
is($c->get('T_PERM'), '100', 'new key appended');

# comments preserved
open my $in, '<', $f; my $body = do { local $/; <$in> }; close $in;
like($body, qr/# Testing flag/, 'comment preserved');
like($body, qr/# a comment/, 'inner comment preserved');

# --- rejects invalid keys and strips newlines from values ---
my ($bad) = CSF2::Config->save_keys($f, { 'bad key' => 'x' });
ok(!$bad, 'invalid key rejected');
CSF2::Config->save_keys($f, { TCP_IN => "22\n80injection" });
my $c2 = CSF2::Config->loadconfig(file => $f);
unlike($c2->get('TCP_IN'), qr/\n/, 'newline stripped from value');

# --- idempotent: saving same value twice is stable ---
CSF2::Config->save_keys($f, { TESTING => '0' });
CSF2::Config->save_keys($f, { TESTING => '0' });
is(CSF2::Config->loadconfig(file => $f)->get('TESTING'), '0', 'idempotent save');

done_testing();
