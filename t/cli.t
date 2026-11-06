use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempdir);

my $dir = tempdir(CLEANUP => 1);
mkdir "$dir/etc"; mkdir "$dir/var";
open my $cf, '>', "$dir/etc/csf.conf" or die $!;
print {$cf} "TESTING = \"0\"\nINPUT_POLICY = \"drop\"\nTCP_IN = \"22,80,443\"\nMGMT_PORTS = \"22\"\n";
close $cf;

my $bin = "$Bin/../bin/csf2";
$ENV{CSF2_ETC}    = "$dir/etc";
$ENV{CSF2_VAR}    = "$dir/var";
$ENV{CSF2_DRYRUN} = 1;
$ENV{SSH_CONNECTION} = '203.0.113.5 54321 10.0.0.1 22';

sub csf { my @a = @_; return scalar `$^X "$bin" @a 2>&1`; }

my $want = do { open my $vf, '<', "$Bin/../VERSION" or die; my $l = <$vf>; $l =~ s/\s+//g; $l };
like(csf(q{-v}), qr/v\Q$want\E/, q{version matches the VERSION file});

# regression: binaries must carry the absolute install lib path so they work
# when invoked via the /usr/sbin/csf symlink (FindBin does not follow symlinks).
for my $b (qw(csf2 lfd2)) {
    open my $bf, '<', "$Bin/../bin/$b" or die "open $b: $!";
    my $src = do { local $/; <$bf> }; close $bf;
    like($src, qr{use lib [^\n]*'/usr/local/csf/lib'}, "$b includes absolute /usr/local/csf/lib");
}
like(csf('-h'), qr/Core Shield Firewall/, 'help');

# deny / duplicate / remove
like(csf('-d', '185.203.44.19', 'ssh', 'brute'), qr/added to the deny list and blocked/, 'deny');
like(csf('-d', '185.203.44.19'), qr/already in csf\.deny/, 'duplicate deny rejected');
# remove an IPv6 entry by a different (non-canonical) spelling of the same host
csf('-d', '2001:0db8::1', 'v6 attacker');
like(csf('-dr', '2001:DB8:0000::1'), qr/removed from the deny list/, 'denyrm by non-canonical v6 spelling');
like(csf('-dr', '185.203.44.19'), qr/removed from the deny list/, 'denyrm removes the IPv4 entry');

# allow
like(csf('-a', '198.51.100.0/24', 'office'), qr/added to the allow list/, 'allow CIDR');

# tempdeny with human ttl
like(csf('-td', '10.0.0.9', '30m', 'lfd'), qr/temporarily denied for 1800s/, 'tempdeny 30m -> 1800s');
like(csf('-tr', '10.0.0.9'), qr/removed temporary entry/, 'temprm');

# invalid IP
like(csf('-d', 'not-an-ip'), qr/not a valid IP/, 'invalid IP rejected');

# status
like(csf('-l'), qr/nftables table inet csf/, 'status output');
like(csf('-l'), qr/enforcing\s+:\s+yes/, 'status shows enforcing');

# inspect
csf('-d', '5.6.7.8', 'scanner');
like(csf('inspect', '5.6.7.8'), qr/State\s+:\s+BLOCKED/, 'inspect shows blocked');

# reload passes lockout guard (SSH safe)
like(csf('-r'), qr/ruleset applied atomically|generated and validated/, 'reload ok when safe');

# reload refused when admin would be locked out
{
    local $ENV{SSH_CONNECTION} = '9.9.9.9 40000 10.0.0.1 2222'; # port 2222 not open, IP not allowed
    like(csf('-r'), qr/ERROR.*lockout guard refused/s, 'reload refused on lockout risk');
    like(csf('-r', '--force'), qr/applied atomically|generated and validated/, 'force overrides lockout');
}

# safe-reload prints the confirm window and --confirm writes the marker
like(csf('--safe-reload'), qr/SAFE RELOAD active.*--confirm/s, 'safe-reload announces watchdog window');
like(csf('--confirm'), qr/safe-reload confirmed/, 'confirm writes marker');
ok(-e "$dir/var/csf.confirmed", 'confirm file created');

# --generate dumps a ruleset; --initdown reports table removal
like(csf('--generate'), qr/table inet csf \{/, 'generate dumps ruleset');
like(csf('--initdown'), qr/table inet csf removed|nothing to remove/, 'initdown');

like(csf("--selftest"), qr/self-test.*VERDICT/s, "selftest prints a verdict");

done_testing();
