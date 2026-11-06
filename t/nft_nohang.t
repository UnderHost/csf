use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use CSF2::Nft;

# Regression: loading a large set must NOT deadlock. Before 2.1.5, _run_stdin
# fed nft over a stdin pipe; a script bigger than the OS pipe buffer (~64KB)
# blocked forever because nft's output was never drained while we kept writing.
# A Threat-Intel set holds tens of thousands of elements, so this hung every
# --ti-update and the hourly cron stacked hung processes until the box died.
#
# We use a fake "nft" that ignores its args and exits 0 WITHOUT reading stdin -
# exactly the condition that deadlocks a pipe. With the temp-file fix there is
# no pipe, so this returns immediately.

my $true = (-x '/usr/bin/true') ? '/usr/bin/true'
         : (-x '/bin/true')     ? '/bin/true'
         : undef;
plan skip_all => 'no /bin/true available' unless $true;

my $nft = CSF2::Nft->new(nft => $true);   # dry_run OFF - really exec

# ~150KB script: far larger than a 64KB pipe buffer
my @elems;
for my $a (0 .. 255) { for my $b (0 .. 40) { push @elems, "10.$a.$b.0/24" } }
cmp_ok(scalar(@elems), '>', 8000, 'built a large element set');

my $done = 0;
eval {
    local $SIG{ALRM} = sub { die "DEADLOCK\n" };
    alarm 20;
    my ($ok) = $nft->load_set('csf_ti_high4', \@elems);
    alarm 0;
    $done = 1;
    ok(defined $ok, 'load_set returned (no deadlock) for a large set');
};
alarm 0;
ok($done, 'large set load completed without hanging') or diag($@);

done_testing();
