use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use CSF2::State;
use CSF2::Nft;
use CSF2::Health;

my $dir = tempdir(CLEANUP => 1);
mkdir "$dir/etc"; mkdir "$dir/var";
my $state = CSF2::State->new(etc => "$dir/etc", var => "$dir/var");
my $nft   = CSF2::Nft->new(dry_run => 1, nft => '/usr/sbin/nft');

sub by_name { my ($r,$n) = @_; my ($h) = grep { $_->{name} eq $n } @$r; return $h }

# --- healthy-ish config (dry-run => nft binary is 'warn') ---
{
    my %cfg = (TCP_IN => '22,80,443', MGMT_PORTS => '22', INPUT_POLICY => 'drop',
               TESTING => 0, IPV6 => 1);
    my ($r, $worst) = CSF2::Health::check(\%cfg, $nft, $state);
    is(by_name($r,'management ports')->{status}, 'ok', 'mgmt ports covered');
    is(by_name($r,'input policy')->{status}, 'ok', 'input policy ok');
    is(by_name($r,'enforcement')->{status}, 'ok', 'enforcing ok');
    is(by_name($r,'IPv6')->{status}, 'ok', 'ipv6 ok');
    is(by_name($r,'ruleset build')->{status}, 'ok', 'ruleset builds');
    is(by_name($r,'ruleset validate')->{status}, 'ok', 'ruleset validates (dry-run)');
    # dry-run nft => warn overall (no enforcement) at worst
    ok($worst eq 'warn' || $worst eq 'ok', "worst is warn/ok: $worst");
}

# --- lockout-risk config: SSH mgmt port not open ---
{
    my %cfg = (TCP_IN => '80,443', MGMT_PORTS => '22', INPUT_POLICY => 'drop',
               TESTING => 0, IPV6 => 1);
    my ($r) = CSF2::Health::check(\%cfg, $nft, $state);
    is(by_name($r,'management ports')->{status}, 'warn', 'warns when mgmt port closed');
    like(by_name($r,'management ports')->{detail}, qr/22/, 'names the missing port');
}

# --- TESTING mode flagged ---
{
    my %cfg = (TCP_IN => '22', MGMT_PORTS => '22', TESTING => 1, IPV6 => 1);
    my ($r) = CSF2::Health::check(\%cfg, $nft, $state);
    is(by_name($r,'enforcement')->{status}, 'warn', 'TESTING flagged as warn');
}

# --- empty TCP_IN + bad policy => fail ---
{
    my %cfg = (TCP_IN => '', MGMT_PORTS => '', INPUT_POLICY => 'bogus', TESTING => 0, IPV6 => 0);
    my ($r, $worst) = CSF2::Health::check(\%cfg, $nft, $state);
    is(by_name($r,'TCP_IN')->{status}, 'warn', 'empty TCP_IN warns');
    is(by_name($r,'input policy')->{status}, 'fail', 'bad policy fails');
    is(by_name($r,'IPv6')->{status}, 'warn', 'ipv6 disabled warns');
    is($worst, 'fail', 'worst is fail');
}

# --- port range covers mgmt port ---
{
    my %cfg = (TCP_IN => '20:1024', MGMT_PORTS => '22', INPUT_POLICY => 'drop', TESTING => 0, IPV6 => 1);
    my ($r) = CSF2::Health::check(\%cfg, $nft, $state);
    is(by_name($r,'management ports')->{status}, 'ok', 'range covers mgmt port');
}

# --- table-not-loaded severity depends on enforcement ---
{
    package FakeNft;
    sub new { my ($c,%o)=@_; bless { dry_run=>0, avail=>1, table=>$o{table} }, $c }
    sub available    { $_[0]{avail} }
    sub table_exists { $_[0]{table} }
    sub validate     { return (1, 'ok') }
}
my $absent = FakeNft->new(table => 0);
my ($re) = CSF2::Health::check(
    { TESTING => 0, TCP_IN => '22', MGMT_PORTS => '22', INPUT_POLICY => 'drop', IPV6 => 1 },
    $absent, $state);
is(by_name($re,'table inet csf')->{status}, 'fail', 'table missing while enforcing => fail');
my ($rt) = CSF2::Health::check(
    { TESTING => 1, TCP_IN => '22', MGMT_PORTS => '22', INPUT_POLICY => 'drop', IPV6 => 1 },
    $absent, $state);
is(by_name($rt,'table inet csf')->{status}, 'warn', 'table missing in TESTING => warn (not fail)');
my $present = FakeNft->new(table => 1);
my ($rp) = CSF2::Health::check(
    { TESTING => 0, TCP_IN => '22', MGMT_PORTS => '22', INPUT_POLICY => 'drop', IPV6 => 1 },
    $present, $state);
is(by_name($rp,'table inet csf')->{status}, 'ok', 'table loaded => ok');

done_testing();
