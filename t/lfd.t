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
use CSF2::Detect;
use CSF2::Risk;
use CSF2::LFD;

my $dir = tempdir(CLEANUP => 1);
mkdir "$dir/etc"; mkdir "$dir/var";
open my $cf, '>', "$dir/etc/csf.conf"; print {$cf} "TESTING=\"0\"\nTCP_IN=\"22\"\n"; close $cf;
# trust one office network
open my $ig, '>', "$dir/etc/csf.allow"; print {$ig} "198.51.100.0/24 # office\n"; close $ig;

my $config = CSF2::Config->loadconfig(file => "$dir/etc/csf.conf");
my $state  = CSF2::State->new(etc => "$dir/etc", var => "$dir/var");
my $nft    = CSF2::Nft->new(dry_run => 1, nft => '/usr/sbin/nft');
my $eng    = CSF2::Engine->new(config => $config, state => $state, nft => $nft);

# low threshold so 3 ssh failures (10 each) cross the short-block line at 30
my $risk = CSF2::Risk->new(T_SHORT_BLOCK => 30, T_LONG_BLOCK => 200, T_PERM => 300,
                           ESCALATION => [300, 1800], PERM_AFTER => 3);
my $lfd = CSF2::LFD->new(engine => $eng, state => $state, risk => $risk,
                         detect => CSF2::Detect->new, var => "$dir/var",
                         server_ips => ['10.0.0.1']);

my $now = 5_000_000;
my $atk = 'sshd[1]: Failed password for root from 45.9.148.7 port 22 ssh2';

# two failures: still monitoring (score 20 < 30)
my @a1 = $lfd->process_line($atk, $now);
is($a1[0]{action}, 'monitor', 'first failure monitored');
my @a2 = $lfd->process_line($atk, $now);
is($a2[0]{action}, 'monitor', 'second failure still monitored');

# third failure crosses threshold -> temp block, escalation rung 1 = 300s
my @a3 = $lfd->process_line($atk, $now);
is($a3[0]{action}, 'temp', 'third failure triggers temp block');
is($a3[0]{timeout}, 300, 'first block uses 5m rung');
ok($a3[0]{score} >= 30, 'score at/above threshold');
ok($state->in_list('deny', '45.9.148.7') || (grep { $_->{ip} eq '45.9.148.7' } @{ $state->temp_load() }),
   'attacker recorded as temp-blocked in state');
is(join(' ', @{$nft->log->[-1]}), '/usr/sbin/nft add element inet csf csf_temp4 { 45.9.148.7 timeout 300s }',
   'LFD pushed a native-timeout element to the kernel');

# --- ignore: allowed office IP is never blocked ---
my @ig = $lfd->process_line('sshd[1]: Failed password for root from 198.51.100.50 port 22 ssh2', $now);
is($ig[0]{action}, 'ignored', 'allow-listed IP ignored');
is($ig[0]{reason}, 'allow list', 'ignored reason = allow list');

# --- server's own IP ignored ---
my @srv = $lfd->process_line('sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2', $now);
is($srv[0]{action}, 'ignored', 'server IP ignored');

# --- correlation across services accelerates blocking ---
my $risk2 = CSF2::Risk->new(T_SHORT_BLOCK => 30);
my $lfd2 = CSF2::LFD->new(engine => $eng, state => $state, risk => $risk2,
                          detect => CSF2::Detect->new, var => "$dir/var");
$lfd2->process_line('cphulkd: FAILED LOGIN for user root from 5.5.5.5', $now);      # +15
my @corr = $lfd2->process_line('dovecot_login authenticator failed for (x) [5.5.5.5]: 535 Incorrect authentication data', $now); # +10 = 25
is($corr[0]{action}, 'monitor', '25 still monitor');
my @corr2 = $lfd2->process_line('sshd[1]: Invalid user admin from 5.5.5.5', $now);  # +12 = 37 -> block
is($corr2[0]{action}, 'temp', 'cross-service correlation triggers block');

# --- incremental tail + rotation ---
my $log = "$dir/var/test.log";
open my $lh, '>', $log; print {$lh} "line one\nline two\n"; close $lh;
my $tl = CSF2::LFD->new(var => "$dir/var");
my @n1 = $tl->tail_new($log);
is(scalar(@n1), 2, 'tail reads 2 initial lines');
open my $lh2, '>>', $log; print {$lh2} "line three\n"; close $lh2;
my @n2 = $tl->tail_new($log);
is_deeply(\@n2, ['line three'], 'tail reads only new line');
# rotation (truncate) resets cursor
open my $lh3, '>', $log; print {$lh3} "fresh\n"; close $lh3;
my @n3 = $tl->tail_new($log);
is_deeply(\@n3, ['fresh'], 'tail resets after rotation');

# --- cursor persistence ---
ok($tl->save_cursors, 'cursors saved');
my $tl2 = CSF2::LFD->new(var => "$dir/var");
ok($tl2->load_cursors, 'cursors loaded');
is($tl2->{cursors}{$log}, $tl->{cursors}{$log}, 'cursor position restored');

# --- systemd journal source (Debian 12+ has no auth.log) ---
my $jr = tempdir(CLEANUP => 1);
mkdir "$jr/usr"; mkdir "$jr/usr/bin"; mkdir "$jr/var"; mkdir "$jr/var/log";
my $jc = "$jr/usr/bin/journalctl";
open my $jf, '>', $jc; print {$jf} <<'SH'; close $jf; chmod 0755, $jc;
#!/bin/sh
echo "$@" > "$(dirname "$0")/args"
echo "Nov 06 10:38:08 host sshd-session[901]: Invalid user admin from 203.0.113.77 port 51234"
echo "-- cursor: s=abc;i=42"
SH
ok(CSF2::LFD->journal_wanted(root => $jr), 'journal used when there is no auth.log / secure');
open my $al, '>', "$jr/var/log/auth.log"; close $al;
ok(!CSF2::LFD->journal_wanted(root => $jr), 'journal not needed when auth.log exists');
ok(CSF2::LFD->journal_wanted(root => $jr, mode => '1'), 'LF_JOURNAL=1 forces the journal');
ok(!CSF2::LFD->journal_wanted(root => $jr, mode => '0'), 'LF_JOURNAL=0 turns it off');
ok(!CSF2::LFD->journal_wanted(root => "$jr/none"), 'no journalctl, no journal');
SKIP: {
    skip 'shell scripts not executable here', 4 unless -x $jc && `$jc` =~ /cursor/;
    my $jl = CSF2::LFD->new(var => "$dir/var", journal => 1, journalctl => $jc);
    my @jlines = $jl->journal_new;
    is(scalar @jlines, 1, 'journal line read, cursor line consumed');
    is($jl->{cursors}{journal}, 's=abc;i=42', 'journal cursor kept');
    my @ev = CSF2::Detect->new->scan($jlines[0]);
    is($ev[0]{source_ip}, '203.0.113.77', 'sshd-session journal line is detected');
    $jl->journal_new;
    open my $af, '<', "$jr/usr/bin/args"; my $args = <$af>; close $af;
    like($args, qr/--after-cursor=s=abc;i=42/, 'next read continues after the cursor');
}

done_testing();
