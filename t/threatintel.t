use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use CSF2::ThreatIntel;
use CSF2::Nft;

# --- registry ---
my @f = CSF2::ThreatIntel::feeds;
ok(@f >= 7, 'several feeds registered');
ok(CSF2::ThreatIntel::feed('spamhaus_drop4'), 'spamhaus_drop4 exists');
is(CSF2::ThreatIntel::feed('spamhaus_drop4')->{category}, 'high', 'spamhaus is high category');
is(CSF2::ThreatIntel::feed('feodo')->{category}, 'botnet', 'feodo is botnet');
is(CSF2::ThreatIntel::feed('cins')->{category}, 'attackers', 'cins is attackers');
is($CSF2::ThreatIntel::CATEGORY{high}{policy}, 'inout', 'high policy inout');
is($CSF2::ThreatIntel::CATEGORY{botnet}{policy}, 'out', 'botnet policy out');

# --- feed_enabled: master switch + per-feed override + default ---
ok(!CSF2::ThreatIntel::feed_enabled({}, CSF2::ThreatIntel::feed('feodo')), 'disabled when TI_ENABLE off');
ok(CSF2::ThreatIntel::feed_enabled({TI_ENABLE=>1}, CSF2::ThreatIntel::feed('feodo')), 'default-on feed enabled');
ok(!CSF2::ThreatIntel::feed_enabled({TI_ENABLE=>1}, CSF2::ThreatIntel::feed('blocklist_all')), 'default-off feed disabled');
ok(CSF2::ThreatIntel::feed_enabled({TI_ENABLE=>1, TI_BLOCKLIST_ALL=>1}, CSF2::ThreatIntel::feed('blocklist_all')), 'per-feed override on');
ok(!CSF2::ThreatIntel::feed_enabled({TI_ENABLE=>1, TI_FEODO=>0}, CSF2::ThreatIntel::feed('feodo')), 'per-feed override off');

# --- parse plaintext (comments, extra columns, invalid lines) ---
my $txt = <<'TXT';
# a comment
1.2.3.4
5.6.7.0/24 ; trailing
10.0.0.1 99            (ipsum second column ignored)
not-an-ip
1.2.3.4
2001:db8::1
TXT
my $p = CSF2::ThreatIntel::parse_feed($txt, 'plaintext');
is_deeply($p, ['1.2.3.4','5.6.7.0/24','10.0.0.1','2001:db8::1'], 'plaintext parsed, deduped, validated');

# --- parse Spamhaus JSON ---
my $json = qq({"cidr":"192.0.2.0/24","sblid":"x"}\n{"cidr":"198.51.100.0/22"}\n{"type":"metadata"}\n);
is_deeply(CSF2::ThreatIntel::parse_feed($json, 'spamhaus_json'), ['192.0.2.0/24','198.51.100.0/22'], 'spamhaus json cidrs extracted');

# --- update() with injected fetch loads sets (dry-run nft records) ---
my $dir = tempdir(CLEANUP => 1); mkdir "$dir/var";
my $nft = CSF2::Nft->new(dry_run => 1, nft => '/usr/sbin/nft');
my %fake = (
    'https://www.spamhaus.org/drop/drop_v4.json' => qq({"cidr":"192.0.2.0/24"}\n),
    'https://feodotracker.abuse.ch/downloads/ipblocklist.txt' => "45.9.148.7\n",
    'https://cinsscore.com/list/ci-badguys.txt' => "185.203.44.19\n",
    'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt' => "185.203.44.19\n5.5.5.5 8\n",
);
my $rep = CSF2::ThreatIntel::update(
    nft => $nft, var => "$dir/var",
    cfg => { TI_ENABLE => 1 },
    only => [qw(spamhaus_drop4 feodo cins ipsum3)],
    fetch => sub { my $u = shift; return $fake{$u} },
);
my %byid = map { $_->{id} => $_ } @{ $rep->{feeds} };
ok($byid{spamhaus_drop4}{ok} && $byid{spamhaus_drop4}{count}==1, 'spamhaus loaded 1');
ok($byid{feodo}{ok} && $byid{feodo}{count}==1, 'feodo loaded 1');
# cins + ipsum share the attackers4 set; 185.203.44.19 dedupes, 5.5.5.5 adds -> 2
my ($att) = grep { "@$_" =~ /load_set.*csf_ti_attackers4/ } @{ $nft->log };
ok($att, 'attackers4 set was loaded');
# high4 got the spamhaus cidr
my ($high) = grep { "@$_" =~ /load_set.*csf_ti_high4/ } @{ $nft->log };
ok($high, 'high4 set was loaded');

# --- status round-trip ---
my $st = CSF2::ThreatIntel::status("$dir/var");
ok($st->{updated} > 0, 'status has update time');
ok($st->{total} >= 3, 'status total entries');

# --- download failure is non-fatal ---
my $rep2 = CSF2::ThreatIntel::update(
    nft => $nft, var => "$dir/var", cfg => { TI_ENABLE => 1 },
    only => ['feodo'], fetch => sub { return '' },
);
is($rep2->{feeds}[0]{ok}, 0, 'failed download reported, not fatal');

done_testing();
