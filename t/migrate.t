use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use CSF2::Migrate;
use CSF2::Config;

my $dir = tempdir(CLEANUP => 1);
mkdir "$dir/legacy"; mkdir "$dir/target";

# a realistic slice of a legacy csf.conf
open my $c, '>', "$dir/legacy/csf.conf"; print {$c} <<'CONF'; close $c;
TESTING = "0"
IPV6 = "1"
TCP_IN = "22,80,443,2087"
UDP_IN = "53"
TCP_OUT = "1:65535"
LF_PARSE = "5"
LF_TRIGGER = "10"
LF_SSHD = "5"
LF_FTPD = "10"
IPTABLES = "/sbin/iptables"
IP6TABLES = "/sbin/ip6tables"
IPSET = "/sbin/ipset"
USE_IPSET = "1"
LF_IPSET_MAXELEM = "65536"
WAITLOCK = "1"
CC_DENY = "CN,RU"
CONF

open my $a, '>', "$dir/legacy/csf.allow"; print {$a} "203.0.113.7 # office\n2001:0db8::1 # v6\n2001:db8:0000::1 # dup spelling\n"; close $a;
open my $de, '>', "$dir/legacy/csf.deny"; print {$de} "185.203.44.19 # attacker\n10.0.0.0/8\n"; close $de;
open my $ig, '>', "$dir/legacy/csf.ignore"; print {$ig} "127.0.0.1\n"; close $ig;

my $m = CSF2::Migrate->new(legacy_etc => "$dir/legacy", target_etc => "$dir/target",
                           backup_dir => "$dir/backup");

# --- analyze (pure) ---
my ($new, $rep) = $m->analyze;

# direct carries
is($new->{TCP_IN}, '22,80,443,2087', 'TCP_IN carried directly');
is($new->{IPV6}, '1', 'IPV6 carried');
is($new->{TESTING}, '0', 'TESTING carried');

# deprecated dropped
ok(!exists $new->{IPTABLES}, 'IPTABLES dropped');
ok(!exists $new->{IPSET}, 'IPSET dropped');
ok(!exists $new->{USE_IPSET}, 'USE_IPSET dropped');
ok(!exists $new->{WAITLOCK}, 'WAITLOCK dropped');
ok((grep { /IPTABLES dropped/ } @{$rep->{deprecated}}), 'deprecation reported for IPTABLES');
ok($rep->{count_deprecated} >= 5, 'several deprecated keys');

# converted
is($new->{RISK_LEGACY_TRIGGER}, '10', 'LF_TRIGGER converted to RISK_LEGACY_TRIGGER');
ok((grep { /LF_TRIGGER -> RISK_LEGACY_TRIGGER/ } @{$rep->{converted}}), 'conversion reported');

# LF_* thresholds flagged for manual review but still carried
is($new->{LF_SSHD}, '5', 'LF_SSHD carried');
ok((grep { /LF_SSHD/ } @{$rep->{manual}}), 'LF_SSHD flagged for manual review');

# unknown key preserved (nothing silently lost)
is($new->{CC_DENY}, 'CN,RU', 'unknown key preserved');

# 2.0 invariants injected
is($new->{CONFIG_VERSION}, '2.0', 'config version set to 2.0');
is($new->{INPUT_POLICY}, 'drop', 'input policy defaulted');
like($new->{MGMT_PORTS}, qr/2087/, 'mgmt ports present');

# --- backup ---
my ($bok, $bpath) = $m->backup;
ok($bok, 'backup ok');
ok(-e "$bpath/csf.conf", 'legacy csf.conf backed up');
ok(-e "$bpath/csf.deny", 'legacy csf.deny backed up');

# --- import lists (canonical + dedup) ---
my $counts = $m->import_lists;
is($counts->{allow}, 2, 'allow deduped to 2 (v6 dup collapsed)');
is($counts->{deny}, 2, 'deny has 2 entries');
open my $af, '<', "$dir/target/csf.allow"; my @al = <$af>; close $af;
ok((grep { /2001:db8::1/ } @al), 'v6 allow canonicalised');
ok(!(grep { /0db8/ } @al), 'no non-canonical v6 spelling remains');

# --- write config ---
my ($wok, $wpath) = $m->write_config($new);
ok($wok, 'config written');
my $reload = CSF2::Config->loadconfig(file => $wpath);
is($reload->get('TCP_IN'), '22,80,443,2087', 'written config reloads (TCP_IN)');
is($reload->get('CONFIG_VERSION'), '2.0', 'written config version 2.0');

done_testing();
