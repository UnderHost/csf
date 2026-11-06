use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use CSF2::State;

my $dir = tempdir(CLEANUP => 1);
mkdir "$dir/etc"; mkdir "$dir/var";
my $st = CSF2::State->new(etc => "$dir/etc", var => "$dir/var");

# --- deny list add/dedup/canonicalise ---
my ($ok, $msg) = $st->add_to_list('deny', '185.203.44.19', 'SSH brute force');
ok($ok, "add deny: $msg");

# same IP, different spelling should be caught as duplicate after canonicalisation
($ok) = $st->add_to_list('deny', '2001:0db8::1', 'v6 attacker');
ok($ok, 'add v6 deny');
my ($dup, $dmsg) = $st->add_to_list('deny', '2001:db8:0000::1', 'dup spelling');
ok(!$dup, "duplicate v6 spelling rejected: $dmsg");

# in_list matches by canonical form regardless of spelling
is($st->in_list('deny', '2001:DB8::1'), '2001:db8::1', 'in_list canonical match');
is($st->in_list('deny', '8.8.8.8'), undef, 'in_list miss');

my $deny = $st->load_list('deny');
is(scalar(@$deny), 2, 'deny list has 2 unique entries');

# --- remove by a non-canonical (differently-spelled) IPv6 address ---
($ok, $msg) = $st->remove_from_list('deny', '2001:0DB8:0000::1'); # same host, other spelling
ok($ok, "remove by non-canonical spelling: $msg");
is(scalar(@{ $st->load_list('deny') }), 1, 'one entry left after remove');

# --- CIDR allow ---
($ok) = $st->add_to_list('allow', '198.51.100.0/24', 'office');
ok($ok, 'add CIDR allow');
my $allow = $st->load_list('allow');
is($allow->[0]{canonical}, '198.51.100.0/24', 'CIDR stored canonical');
is($allow->[0]{kind}, 'cidr', 'CIDR kind recorded');

# --- invalid input ---
($ok, $msg) = $st->add_to_list('deny', 'not-an-ip');
ok(!$ok, "invalid address rejected: $msg");

# --- temp bans with expiry ---
($ok) = $st->temp_add(ip => '10.0.0.9', kind => 'deny', timeout => 3600, comment => 'lfd ssh');
ok($ok, 'temp add live');
# Inject a genuinely-aged record (epoch 100s ago, 1s timeout) to exercise purge.
{
    open my $fh, '>>', "$dir/var/csf.tempban" or die $!;
    print {$fh} join('|', time - 100, '10.0.0.10', 4, 'deny', 1, '', 'aged') . "\n";
    close $fh;
}
my $temps = $st->temp_load();               # purges expired from file, returns all seen
my ($live)   = grep { $_->{ip} eq '10.0.0.9' }  @$temps;
my ($expd)   = grep { $_->{ip} eq '10.0.0.10' } @$temps;
ok($live && !$live->{expired}, 'live temp ban present and not expired');
ok($expd && $expd->{expired}, 'zero-timeout ban marked expired');
# after purge, reload should not contain the expired one
my $temps2 = $st->temp_load();
ok(!(grep { $_->{ip} eq '10.0.0.10' } @$temps2), 'expired ban purged from store');
ok((grep { $_->{ip} eq '10.0.0.9' } @$temps2), 'live ban retained');

# --- repeat temp ban (LFD escalation): one entry, the later expiry wins ---
$st->temp_add(ip => q{10.0.0.11}, kind => q{deny}, timeout => 300, comment => q{first});
my (undef, undef, $eff) = $st->temp_add(ip => '10.0.0.11', kind => 'deny', timeout => 7200, comment => 'escalated');
ok($eff >= 7199 && $eff <= 7200, 'longer repeat ban extends the block');
(undef, undef, $eff) = $st->temp_add(ip => '10.0.0.11', kind => 'deny', timeout => 60, comment => 'shorter');
ok($eff > 7000, 'shorter repeat ban never shortens an existing block');
is(scalar(grep { $_->{ip} eq '10.0.0.11' } @{ $st->temp_load }), 1, 'repeat bans keep a single entry');

# --- state_for_ruleset partitions correctly ---
$st->add_to_list('deny', '2001:db8::bad', 'v6');
my $state = $st->state_for_ruleset();
ok((grep { $_ eq '198.51.100.0/24' } @{ $state->{allow4} }), 'allow4 partition');
ok((grep { $_ eq '2001:db8::bad' }   @{ $state->{deny6} }),  'deny6 partition');
ok((grep { $_->{ip} eq '10.0.0.9' }  @{ $state->{temp} }),   'temp partition');
my ($tr) = grep { $_->{ip} eq '10.0.0.9' } @{ $state->{temp} };
ok($tr->{timeout} >= 1 && $tr->{timeout} <= 3600, 'temp remaining timeout within range');

done_testing();
