use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use CSF2::Ruleset;
use CSF2::State;
use CSF2::Nft;
use CSF2::Engine;
use CSF2::Config;

# --- custom include hooks survive regeneration ---
{
    my $s = CSF2::Ruleset::build(
        { TCP_IN => '22', IPV6 => 0,
          INCLUDE_INPUT  => "tcp dport 8080 accept\nip saddr 10.9.9.9 drop",
          INCLUDE_OUTPUT => "tcp dport 25 accept" },
        {},
    );
    like($s, qr/tcp dport 8080 accept/, 'input include injected');
    like($s, qr/ip saddr 10\.9\.9\.9 drop/, 'multi-line input include');
    # include sits before the marker, inside the input chain
    ok(index($s, 'tcp dport 8080 accept') < index($s, '# csf_include_input'),
       'include placed before marker');
    like($s, qr/tcp dport 25 accept/, 'output include injected (default-accept path)');

    # arrayref form
    my $s2 = CSF2::Ruleset::build({ TCP_IN => '22', IPV6 => 0,
        INCLUDE_INPUT => ['udp dport 1194 accept'] }, {});
    like($s2, qr/udp dport 1194 accept/, 'arrayref include');
}

# --- snapshot / revert round-trip (dry-run records the apply of the snapshot) ---
{
    my $dir = tempdir(CLEANUP => 1);
    mkdir "$dir/etc"; mkdir "$dir/var";
    my $config = CSF2::Config->loadconfig(file => "$dir/etc/csf.conf");
    my $state  = CSF2::State->new(etc => "$dir/etc", var => "$dir/var");
    my $nft    = CSF2::Nft->new(dry_run => 1, nft => '/usr/sbin/nft');
    my $eng    = CSF2::Engine->new(config => $config, state => $state, nft => $nft);

    my ($ok, $msg) = $eng->snapshot_save("$dir/var/csf.rollback");
    ok($ok, "snapshot saved: $msg");
    ok(-e "$dir/var/csf.rollback", 'rollback file exists');

    # empty snapshot (table absent in dry-run) => revert removes the table
    my ($rok, $rmsg) = $eng->revert_from("$dir/var/csf.rollback");
    ok($rok, "revert ok: $rmsg");

    # non-empty snapshot => revert re-applies it
    open my $fh, '>', "$dir/var/csf.rollback"; print {$fh} "table inet csf { }\n"; close $fh;
    my ($rok2) = $eng->revert_from("$dir/var/csf.rollback");
    ok($rok2, 'revert applies non-empty snapshot');
    is(join(' ', @{$nft->log->[-1]}), '/usr/sbin/nft -f - <<stdin>>', 'revert used nft -f -');

    my ($nok) = $eng->revert_from("$dir/var/does-not-exist");
    ok(!$nok, 'revert fails cleanly when no snapshot');
}

done_testing();
