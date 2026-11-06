use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use CSF2::Lockout;

# ssh_info parsing
{
    my ($ip, $port) = CSF2::Lockout::ssh_info(SSH_CONNECTION => '203.0.113.5 54321 10.0.0.1 22');
    is($ip, '203.0.113.5', 'ssh_info client ip');
    is($port, '22', 'ssh_info server port');
    my ($ip2) = CSF2::Lockout::ssh_info(SSH_CLIENT => '198.51.100.9 40000 2222');
    is($ip2, '198.51.100.9', 'ssh_info falls back to SSH_CLIENT');
}

my $env = { SSH_CONNECTION => '203.0.113.5 54321 10.0.0.1 22' };

# 1) Safe: SSH port open, admin IP not blocked -> ok, no blocks
{
    my $r = CSF2::Lockout::guard(
        { INPUT_POLICY => 'drop', TCP_IN => '22,80,443', MGMT_PORTS => '22,2087' },
        { deny4 => [], allow4 => [], temp => [] },
        env => $env,
    );
    ok($r->{ok}, 'safe config passes');
    is(scalar(@{$r->{blocks}}), 0, 'no blocks');
    # 2087 not open -> a warning
    ok((grep { /management port 2087/ } @{$r->{warnings}}), 'warns missing mgmt port 2087');
}

# 2) Critical: admin IP is in deny set -> block
{
    my $r = CSF2::Lockout::guard(
        { INPUT_POLICY => 'drop', TCP_IN => '22', MGMT_PORTS => '22' },
        { deny4 => ['203.0.113.5'], allow4 => [], temp => [] },
        env => $env,
    );
    ok(!$r->{ok}, 'blocked when admin IP denied');
    ok((grep { /in a deny\/temp set/ } @{$r->{blocks}}), 'block explains denied admin IP');
}

# 2b) admin IP denied via CIDR
{
    my $r = CSF2::Lockout::guard(
        { INPUT_POLICY => 'drop', TCP_IN => '22', MGMT_PORTS => '22' },
        { deny4 => ['203.0.113.0/24'], allow4 => [], temp => [] },
        env => $env,
    );
    ok(!$r->{ok}, 'blocked when admin IP in denied CIDR');
}

# 3) Critical: SSH port NOT open and IP not allowed -> block
{
    my $r = CSF2::Lockout::guard(
        { INPUT_POLICY => 'drop', TCP_IN => '80,443', MGMT_PORTS => '80' },
        { deny4 => [], allow4 => [], temp => [] },
        env => $env,
    );
    ok(!$r->{ok}, 'blocked when SSH port closed and IP not allowed');
    ok((grep { /would be dropped/ } @{$r->{blocks}}), 'block explains dropped SSH');
}

# 3b) SSH port closed BUT admin IP explicitly allowed -> ok
{
    my $r = CSF2::Lockout::guard(
        { INPUT_POLICY => 'drop', TCP_IN => '80,443', MGMT_PORTS => '80' },
        { deny4 => [], allow4 => ['203.0.113.5'], temp => [] },
        env => $env,
    );
    ok($r->{ok}, 'allowed admin IP survives closed SSH port');
}

# 4) force overrides blocks
{
    my $r = CSF2::Lockout::guard(
        { INPUT_POLICY => 'drop', TCP_IN => '80', MGMT_PORTS => '80' },
        { deny4 => ['203.0.113.5'], allow4 => [], temp => [] },
        env => $env, force => 1,
    );
    ok($r->{ok}, 'force overrides critical blocks');
    ok((grep { /OVERRIDDEN by force/ } @{$r->{warnings}}), 'force override warned');
}

# 5) port range entry in TCP_IN covers mgmt port
{
    my $r = CSF2::Lockout::guard(
        { INPUT_POLICY => 'drop', TCP_IN => '20:1024', MGMT_PORTS => '22' },
        { deny4 => [], allow4 => [], temp => [] },
        env => $env,
    );
    ok($r->{ok}, 'port range covers SSH');
    is(scalar(@{$r->{blocks}}), 0, 'no block with range');
}

# 6) policy accept never locks out
{
    my $r = CSF2::Lockout::guard(
        { INPUT_POLICY => 'accept', TCP_IN => '', MGMT_PORTS => '22' },
        { deny4 => ['203.0.113.5'], temp => [] },
        env => $env,
    );
    ok($r->{ok}, 'policy accept always ok');
}

# 7) temp-deny of admin IP blocks
{
    my $r = CSF2::Lockout::guard(
        { INPUT_POLICY => 'drop', TCP_IN => '22', MGMT_PORTS => '22' },
        { deny4 => [], allow4 => [], temp => [ { ip => '203.0.113.5', kind => 'deny' } ] },
        env => $env,
    );
    ok(!$r->{ok}, 'temp-denied admin IP blocks');
}

done_testing();
