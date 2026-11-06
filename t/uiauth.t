use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use CSF2::UIAuth;

my $etc = tempdir(CLEANUP => 1);
my $var = tempdir(CLEANUP => 1);
my $a = CSF2::UIAuth->new(etc => $etc, var => $var, rounds => 1000, now => 1_800_000_000);

# --- base32 + TOTP: RFC 6238 SHA-1 test vectors (secret "12345678901234567890") ---
my $sec = CSF2::UIAuth::base32_encode('12345678901234567890');
is($sec, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'base32 encode');
is(CSF2::UIAuth::base32_decode($sec), '12345678901234567890', 'base32 round trip');
is(CSF2::UIAuth::totp_code($sec, 59),         '287082', 'RFC 6238 T=59');
is(CSF2::UIAuth::totp_code($sec, 1111111109), '081804', 'RFC 6238 T=1111111109');
is(CSF2::UIAuth::totp_code($sec, 2000000000), '279037', 'RFC 6238 T=2000000000');
is(CSF2::UIAuth::base32_decode('not base32!'), undef, 'invalid base32 rejected');

# --- passwords ---
my $h = $a->hash_password('correct horse battery');
like($h, qr/^\$6\$rounds=1000\$/, 'SHA-512 crypt hash');
ok($a->check_password('correct horse battery', $h), 'right password accepted');
ok(!$a->check_password('wrong password here', $h), 'wrong password rejected');
ok(!$a->check_password('x', 'plaintext'), 'non-crypt hash never matches');
ok(CSF2::UIAuth::ct_eq('abc', 'abc') && !CSF2::UIAuth::ct_eq('abc', 'abd') && !CSF2::UIAuth::ct_eq('a', 'ab'), 'constant-time compare');

# --- users ---
my ($ok, $m) = $a->set_user('bad name!', 'long enough password');
ok(!$ok, 'invalid user name refused');
($ok, $m) = $a->set_user('admin', 'short');
ok(!$ok, 'short password refused');
my $secret;
($ok, $m, $secret) = $a->set_user('admin', 'correct horse battery');
ok($ok, 'user created');
like($secret, qr/^[A-Z2-7]{32}$/, 'TOTP secret issued');
my $mode = (stat("$etc/ui.users"))[2] & 07777;
is(sprintf('%o', $mode), '600', 'users file is 0600') unless $^O eq 'cygwin' || $^O eq 'MSWin32';
ok($a->load_users->{admin}, 'user persisted');

# --- login: password + TOTP, throttling, replay ---
my $now = $a->{now};
my $code = CSF2::UIAuth::totp_code($secret, $now);
my ($lok) = $a->login('admin', 'wrong password!!', $code, '198.51.100.7');
ok(!$lok, 'wrong password fails even with a valid code');
($lok) = $a->login('admin', 'correct horse battery', '000000', '198.51.100.7');
ok(!$lok, 'wrong code fails');
($lok) = $a->login('nobody', 'correct horse battery', $code, '198.51.100.7');
ok(!$lok, 'unknown user fails');
($lok) = $a->login('admin', 'correct horse battery', $code, '198.51.100.8');
ok($lok, 'password + valid code succeeds');
($lok) = $a->login('admin', 'correct horse battery', $code, '198.51.100.8');
ok(!$lok, 'the same code cannot be used twice (replay)');

$a->{now} = $now + 30;
($lok) = $a->login('admin', 'correct horse battery', CSF2::UIAuth::totp_code($secret, $now + 30), '198.51.100.8');
ok($lok, 'next 30s step accepted');

for (1 .. 5) { $a->record_failure('203.0.113.5') }
ok($a->is_locked('203.0.113.5'), 'IP locked after 5 failures');
($lok, my $why) = $a->login('admin', 'correct horse battery', CSF2::UIAuth::totp_code($secret, $now + 60), '203.0.113.5');
is($why, 'locked', 'locked IP cannot log in even with valid credentials');
$a->{now} = $now + 30 + 901;
ok(!$a->is_locked('203.0.113.5'), 'lock expires after the window');

# --- sessions ---
$a->{now} = 1_900_000_000;
my $s = $a->create_session('admin');
like($s->{token}, qr/^[0-9a-f]{64}$/, '256-bit session token');
like($s->{csrf}, qr/^[0-9a-f]{32}$/, 'CSRF token issued');
my @files = glob("$var/ui-sessions/s-*");
ok(@files && !grep({ index($_, $s->{token}) >= 0 } @files), 'raw token is never stored on disk');
my $c = $a->check_session($s->{token});
is($c->{user}, 'admin', 'session valid');
is($c->{csrf}, $s->{csrf}, 'session returns its CSRF token');
ok(!$a->check_session('f' x 64), 'unknown token rejected');
ok(!$a->check_session('../../etc/passwd'), 'malformed token rejected');

$a->{now} += $CSF2::UIAuth::IDLE_SECONDS + 1;
ok(!$a->check_session($s->{token}), 'idle session expires');

$a->{now} = 1_900_100_000;
my $s2 = $a->create_session('admin');
$a->del_user('admin');
ok(!$a->check_session($s2->{token}), 'deleting a user ends its sessions');

$a->set_user('admin', 'correct horse battery');
my $s3 = $a->create_session('admin');
ok($a->check_session($s3->{token}), 'recreated user can hold a session');
$a->destroy_session($s3->{token});
ok(!$a->check_session($s3->{token}), 'logout destroys the session');

# --- LFD sees UI brute force ---
require CSF2::Detect;
my @ev = CSF2::Detect->new->scan('2026-11-05 20:01:02 csf2-ui: login failed for user admin from 198.51.100.44');
is(scalar @ev, 1, 'LFD detects a failed UI login');
is($ev[0]{source_ip}, '198.51.100.44', 'attacker IP extracted');
is($ev[0]{service}, 'csf2-ui', 'service csf2-ui');
is(scalar(CSF2::Detect->new->scan('2026-11-05 20:01:02 csf2-ui: login ok for user admin from 198.51.100.44')), 0, 'successful login is not an event');

like($a->otpauth_uri('admin', 'ABC', 'hub.example'), qr{^otpauth://totp/CSF:admin\@hub\.example\?secret=ABC&}, 'otpauth URI');

done_testing();
