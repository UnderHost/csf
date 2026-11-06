use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use CSF2::Profiles;

# four profiles, ordered
my @n = CSF2::Profiles::names;
is_deeply(\@n, [qw(low medium high attack)], 'four profiles in order');

# each has label, tagline, desc, config
for my $name (@n) {
    my $p = CSF2::Profiles::get($name);
    ok($p, "$name exists");
    ok($p->{label} && $p->{tagline} && $p->{desc}, "$name has metadata");
    ok(ref($p->{config}) eq 'HASH', "$name has config");
    is($p->{config}{INPUT_POLICY}, 'drop', "$name pins policy to drop");
    ok(!exists $p->{config}{TESTING}, "$name does not touch TESTING");
    ok(!exists $p->{config}{TCP_IN}, "$name does not touch ports");
}

# monotonic aggressiveness: thresholds drop low > medium > high > attack
my %sb = map { $_ => CSF2::Profiles::get($_)->{config}{T_SHORT_BLOCK} } @n;
ok($sb{low} > $sb{medium} && $sb{medium} > $sb{high} && $sb{high} > $sb{attack},
   'short-block threshold gets stricter low->attack');

# reputation memory grows stricter
my %hl = map { $_ => CSF2::Profiles::get($_)->{config}{HALFLIFE} } @n;
ok($hl{attack} > $hl{high} && $hl{high} > $hl{medium} && $hl{medium} > $hl{low},
   'reputation half-life longer for stricter profiles');

# permanent-block escalation faster for stricter profiles
my %pa = map { $_ => CSF2::Profiles::get($_)->{config}{PERM_AFTER} } @n;
ok($pa{low} > $pa{medium} && $pa{medium} > $pa{high} && $pa{high} > $pa{attack},
   'perm-after fewer offences for stricter profiles');

# config_for returns a copy
my $c = CSF2::Profiles::config_for('high');
$c->{T_PERM} = 999;
isnt(CSF2::Profiles::get('high')->{config}{T_PERM}, 999, 'config_for returns a copy');
is(CSF2::Profiles::config_for('nope'), undef, 'unknown profile undef');

# managed_keys covers the tuning knobs
my %mk = map { $_ => 1 } CSF2::Profiles::managed_keys;
ok($mk{T_SHORT_BLOCK} && $mk{HALFLIFE} && $mk{DROP_LOG} && $mk{PERM_AFTER}, 'managed keys present');

# detect: a config matching medium is detected; a tweaked one is custom
my $medcfg = { %{ CSF2::Profiles::config_for('medium') } };
is(CSF2::Profiles::detect($medcfg), 'medium', 'detects medium');
$medcfg->{T_PERM} = '123';
is(CSF2::Profiles::detect($medcfg), '', 'tweaked config = custom (no match)');
is(CSF2::Profiles::detect({}), '', 'empty config = custom');

done_testing();
