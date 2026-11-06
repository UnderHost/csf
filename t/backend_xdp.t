use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use CSF2::Nft;
use CSF2::XDP;
use CSF2::IP;

# ============================ nft backend / batch =============================
my $nft = CSF2::Nft->new(dry_run => 1, nft => '/usr/sbin/nft');
is($nft->backend, 'nft', 'default backend is nft');

# requesting netlink without a helper falls back to nft (never breaks callers)
my $nl = CSF2::Nft->new(dry_run => 1, backend => 'netlink');
is($nl->backend, 'nft', 'netlink falls back to nft when helper absent');

# batch apply is one atomic transaction, not N forks
my ($bok) = $nft->apply_batch([
    { op => 'add',    set => 'csf_deny4', elem => '1.2.3.4' },
    { op => 'add',    set => 'csf_temp4', elem => '5.6.7.8 timeout 3600s' },
    { op => 'delete', set => 'csf_deny4', elem => '9.9.9.9' },
]);
ok($bok, 'apply_batch ok');
is($nft->log->[-1][0], '<<batch>>', 'batch recorded as one transaction');
is($nft->log->[-1][1], '3 ops', 'batch carried all 3 ops');

my ($eok) = $nft->apply_batch([]);
ok($eok, 'empty batch is a no-op success');

# ============================== XDP fast-drop =================================
# disabled by default => no-op, not available
my $off = CSF2::XDP->new(enabled => 0, dry_run => 1);
ok(!$off->available, 'XDP unavailable when disabled');
ok(!$off->drop_add('1.2.3.4'), 'drop_add no-op when disabled');

# enabled + dry-run => available, builds correct bpftool commands
my $xdp = CSF2::XDP->new(enabled => 1, dry_run => 1, bpftool => '/usr/sbin/bpftool',
                         map4 => '/sys/fs/bpf/csf/deny4', map6 => '/sys/fs/bpf/csf/deny6');
ok($xdp->available, 'XDP available when enabled (dry-run)');

# IPv4 key bytes: 45.9.148.7 -> 0x2d 0x09 0x94 0x07
ok($xdp->drop_add('45.9.148.7'), 'drop_add v4 ok');
my $cmd = join(' ', @{ $xdp->log->[-1] });
like($cmd, qr{/usr/sbin/bpftool map update pinned /sys/fs/bpf/csf/deny4 key 0x2d 0x09 0x94 0x07 value 0x01 any},
     'v4 map update command + network-order key bytes');

# IPv6 goes to the v6 map with a 16-byte key
$xdp->drop_add('2001:db8::1');
my $cmd6 = join(' ', @{ $xdp->log->[-1] });
like($cmd6, qr{pinned /sys/fs/bpf/csf/deny6 key 0x20 0x01 0x0d 0xb8}, 'v6 map + key prefix bytes');
my ($keypart) = $cmd6 =~ /key (.*) value/;
my @bytes = ($keypart =~ /0x[0-9a-f]{2}/g);
is(scalar(@bytes), 16, 'v6 key is 16 bytes');

# delete path
$xdp->drop_del('45.9.148.7');
like(join(' ', @{ $xdp->log->[-1] }), qr{map delete pinned /sys/fs/bpf/csf/deny4 key 0x2d}, 'v4 map delete');

# ===================== Engine wiring: deny also feeds XDP =====================
use CSF2::State; use CSF2::Config; use CSF2::Engine; use File::Temp qw(tempdir);
my $dir = tempdir(CLEANUP => 1); mkdir "$dir/etc"; mkdir "$dir/var";
my $config = CSF2::Config->loadconfig(file => "$dir/etc/csf.conf");
my $state  = CSF2::State->new(etc => "$dir/etc", var => "$dir/var");
my $dnft   = CSF2::Nft->new(dry_run => 1, nft => '/usr/sbin/nft');
my $exdp   = CSF2::XDP->new(enabled => 1, dry_run => 1);
my $eng    = CSF2::Engine->new(config => $config, state => $state, nft => $dnft, xdp => $exdp);

$eng->deny('185.203.44.19', 'severe');
ok((grep { "@$_" =~ /map update pinned .*deny4/ } @{ $exdp->log }), 'permanent deny pushed IP to XDP map');

# CIDR deny must NOT go to XDP (single-address fast-drop only)
my $before = scalar @{ $exdp->log };
$eng->deny('10.0.0.0/8', 'range');
is(scalar @{ $exdp->log }, $before, 'CIDR deny does not touch XDP');

done_testing();
