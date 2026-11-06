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
use CSF2::IP;
use CSF2::Cloudflare;

# Never depend on outbound network in the install gate: force the pinned list.
$ENV{CSF2_CF_OFFLINE} = 1;

my $dir = tempdir(CLEANUP => 1);
mkdir "$dir/etc"; mkdir "$dir/var";
open my $cf, '>', "$dir/etc/csf.conf" or die $!;
print {$cf} <<'CONF';
CONFIG_VERSION = "2.0"
TESTING = "1"
IPV6 = "1"
INPUT_POLICY = "drop"
TCP_IN = "22,80,443"
CONF
close $cf;

my $config = CSF2::Config->loadconfig(file => "$dir/etc/csf.conf");
my $state  = CSF2::State->new(etc => "$dir/etc", var => "$dir/var");
my $nft    = CSF2::Nft->new(dry_run => 1, nft => '/usr/sbin/nft');
my $eng    = CSF2::Engine->new(config => $config, state => $state, nft => $nft);

# fetch() must always yield a usable, valid set of CIDRs (falls back offline)
my @ips = CSF2::Cloudflare::fetch();
ok(@ips >= 5, 'fetch returns a usable set of ranges (' . scalar(@ips) . ')');
my $allvalid = 1;
for my $ip (@ips) { $allvalid = 0 unless CSF2::IP::parse($ip); }
ok($allvalid, 'every Cloudflare range parses as a valid IP/CIDR');
ok((grep { $_ =~ /:/ } @ips), 'includes IPv6 ranges');

# count starts at zero
is(CSF2::Cloudflare::count_active($state), 0, 'no Cloudflare entries initially');

# enable -> ranges land on the allow list, tagged Cloudflare
my ($eok, $emsg, $en) = CSF2::Cloudflare::enable(eng => $eng);
ok($eok, "enable ok: $emsg");
ok($en >= 5, "enable added ranges ($en)");
is(CSF2::Cloudflare::count_active($state), $en, 'count matches added ranges');

my $allow = $state->load_list('allow');
ok((grep { ($_->{comment}//'') =~ /Cloudflare/ } @$allow), 'allow entries tagged Cloudflare');

# a non-Cloudflare allow entry must survive disable
$eng->allow('203.0.113.7', 'my office');
my ($dok, $dmsg, $dn) = CSF2::Cloudflare::disable(eng => $eng, state => $state);
ok($dok, "disable ok: $dmsg");
is(CSF2::Cloudflare::count_active($state), 0, 'all Cloudflare entries removed');
my $after = $state->load_list('allow');
ok((grep { $_->{canonical} eq '203.0.113.7' } @$after), 'non-Cloudflare allow entry preserved');

done_testing();
