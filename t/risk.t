use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use CSF2::Risk;

my $r = CSF2::Risk->new(HALFLIFE => 3600);

# --- accumulation at fixed time ---
my $t0 = 1_000_000;
is($r->add_event('1.2.3.4', 10, $t0), 10, 'first event score 10');
is($r->add_event('1.2.3.4', 12, $t0), 22, 'accumulates to 22');
is($r->score('1.2.3.4', $t0), 22, 'score reads 22');

# --- decay: after one half-life, ~half ---
my $half = $r->score('1.2.3.4', $t0 + 3600);
ok(abs($half - 11) < 0.01, "score halves after HALFLIFE (got $half)");
my $quarter = $r->score('1.2.3.4', $t0 + 7200);
ok(abs($quarter - 5.5) < 0.01, "score quarters after 2x HALFLIFE (got $quarter)");

# --- correlation: many services roll into one IP crossing a block threshold ---
my $c = CSF2::Risk->new;
my $tn = 2_000_000;
$c->add_event('9.9.9.9', 10, $tn);  # ssh
$c->add_event('9.9.9.9', 15, $tn);  # cpanel
$c->add_event('9.9.9.9', 10, $tn);  # smtp
$c->add_event('9.9.9.9', 40, $tn);  # modsec sqli
my $ev = $c->evaluate('9.9.9.9', $tn);
is($ev->{score}, 75, 'correlated score 75');
is($ev->{level}, 'short', 'level short at 75');
ok($ev->{block}, 'block triggered');

# --- level thresholds ---
is($r->level(10),  'clear',    'level clear');
is($r->level(30),  'monitor',  'level monitor');
is($r->level(50),  'throttle', 'level throttle');
is($r->level(70),  'short',    'level short');
is($r->level(90),  'long',     'level long');
is($r->level(120), 'perm',     'level perm');

# --- progressive enforcement ladder ---
my $p = CSF2::Risk->new(ESCALATION => [300, 1800, 21600, 86400], PERM_AFTER => 5);
my $tp = 3_000_000;
is($p->next_timeout('5.5.5.5', $tp), 300, 'offence 1 -> 5m');
is($p->record_block('5.5.5.5', $tp), 300, 'record returns applied 300');
is($p->next_timeout('5.5.5.5', $tp), 1800, 'offence 2 -> 30m');
$p->record_block('5.5.5.5', $tp);
is($p->next_timeout('5.5.5.5', $tp), 21600, 'offence 3 -> 6h');
$p->record_block('5.5.5.5', $tp);
is($p->next_timeout('5.5.5.5', $tp), 86400, 'offence 4 -> 24h');
$p->record_block('5.5.5.5', $tp);
is($p->next_timeout('5.5.5.5', $tp), 0, 'offence 5 -> permanent (0)');

# --- offence forgiveness after OFFENSE_TTL idle ---
my $f = CSF2::Risk->new(ESCALATION => [300, 1800], OFFENSE_TTL => 100);
$f->record_block('7.7.7.7', 100);          # offence 1 at t=100
$f->record_block('7.7.7.7', 150);          # offence 2 at t=150
is($f->next_timeout('7.7.7.7', 160), 0, 'escalated beyond ladder -> perm');
# long idle forgives -> back to first rung
is($f->next_timeout('7.7.7.7', 150 + 1000), 300, 'forgiven after idle -> 5m again');

# --- persistence round-trip ---
{
    my $dir = tempdir(CLEANUP => 1);
    $r->save("$dir/risk.db");
    my $r2 = CSF2::Risk->new(HALFLIFE => 3600);
    ok($r2->load("$dir/risk.db"), 'risk db loaded');
    ok(abs($r2->score('1.2.3.4', $t0) - 22) < 0.5, 'score restored from disk');
}

# --- prune drops decayed-to-zero entries ---
{
    my $g = CSF2::Risk->new(HALFLIFE => 60);
    $g->add_event('8.8.8.8', 10, 0);
    $g->prune(100000);   # far future -> decayed to ~0
    is($g->score('8.8.8.8', 100000), 0, 'pruned entry gone');
}

done_testing();
