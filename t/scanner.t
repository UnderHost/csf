use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use CSF2::Scanner;

sub put { my ($f, @c) = @_; open my $fh, '>', $f or die "$f: $!"; print {$fh} @c; close $fh }
sub slurp { my $f = shift; open my $fh, '<', $f or return ''; local $/; my $c = <$fh>; close $fh; return $c }

# --- a cPanel tree with one site ---
my $R   = tempdir(CLEANUP => 1);
my $var = "$R/var/lib/csf";
make_path("$R/usr/local/cpanel", "$R/etc", "$var/sigs", "$R/home/bob/public_html/wp", "$R/var/log/apache2/domlogs");
put("$R/etc/userdatadomains", "bob.test: bob==root==main==bob.test==/home/bob/public_html==1.2.3.4:80==\n",
                              "addon.test: bob==root==addon==bob.test==/home/bob/public_html/addon==1.2.3.4:80==\n");
my $docroot = "$R/home/bob/public_html";
make_path("$docroot/addon");
put("$docroot/index.php", "<?php echo 'hello';\n");
put("$docroot/wp/shell.php", "<?php eval(base64_decode(\$_POST['x'])); ?>\n");
put("$docroot/wp/evil.php", "<?php /* looks innocent */ \$a=1;\n");
put("$docroot/logo.ico", "GIF89a<?php system(\$_GET['c']); ?>");
put("$docroot/readme.txt", "eval(base64_decode('x'))");          # .txt is not scanned
symlink("/etc/passwd", "$docroot/link.php");

my @ran;
my $clam_out = '';
my $run = sub { my ($argv) = @_; push @ran, $argv; return $argv->[0] =~ /clamscan/ ? $clam_out : '' };

my @blocked;
{ package FakeEngine; sub new { bless {}, shift } sub tempdeny { my (undef, $ip, $ttl, %o) = @_; push @blocked, [$ip, $ttl, $o{comment}]; return (1, 'ok') } }

my $now = time;
my %cfg = (SCAN_ENABLE => 1);
my $sc = CSF2::Scanner->new(root => $R, var => $var, cfg => \%cfg, run => $run, engine => FakeEngine->new,
                            log => '/var/log/csf2-scan.log', now => sub { $now });
make_path("$R/var/log");

is($sc->{platform}, 'cpanel', 'platform detected from the tree');
is_deeply([ $sc->roots ], [ $docroot ], 'cPanel docroots from /etc/userdatadomains; a nested addon docroot is not scanned twice');

# --- candidates ---
my ($files, $trunc) = $sc->candidates(0);
my @names = sort map { (split m{/}, $_)[-1] } @$files;
is_deeply(\@names, [qw(evil.php index.php logo.ico shell.php)], 'scanned extensions only, symlinks skipped');
is($trunc, 0, 'not truncated');
my ($none) = $sc->candidates($now + 10);
is(scalar @$none, 0, 'nothing changed after "since"');

{ local $sc->{cfg}{SCAN_MAX_FILES} = 2;
  my ($f2, $t2, $upto) = $sc->candidates(0);
  is(scalar @$f2, 2, 'per-run file limit');
  ok($t2 && $upto, 'truncation reports where to continue'); }

# A desktop antivirus (e.g. Windows Defender under Cygwin) refuses to open the
# web-shell samples; on Linux they are always readable.
my $av_blocked = !open(my $probe, '<', "$docroot/wp/shell.php");
close $probe if $probe;

# --- heuristics ---
SKIP: {
    skip 'antivirus blocks the malware samples on this machine', 2 if $av_blocked;
    is($sc->heuristic("$docroot/wp/shell.php"), 'CSF.Heur.Eval.Decode', 'obfuscated eval found');
    is($sc->heuristic("$docroot/logo.ico"), 'CSF.Heur.PHPinImage', 'PHP hidden in an image found');
}
is($sc->heuristic("$docroot/index.php"), undef, 'clean file passes');

# --- engines: no binaries -> heuristics only, nothing certain ---
my $hits = $sc->scan($files);
is(scalar(grep { $_->{certain} } @$hits), 0, 'heuristic hits are never certain');
SKIP: { skip 'antivirus blocks the malware samples', 1 if $av_blocked; is(scalar @$hits, 2, 'two heuristic hits'); }

# --- ClamAV hit (fake binary + signature db) ---
make_path("$R/usr/bin"); put("$R/usr/bin/clamscan", "#!/bin/sh\n"); chmod 0755, "$R/usr/bin/clamscan";
put("$var/sigs/rfxn.ndb", "sig\n");
$clam_out = "$docroot/wp/evil.php: {HEX}php.cmdshell.unclassed.365 FOUND\n";
$hits = $sc->scan($files);
my ($evil) = grep { $_->{file} =~ /evil\.php$/ } @$hits;
ok($evil && $evil->{certain} && $evil->{engine} eq 'clamav', 'ClamAV hit is certain');
ok((grep { grep { $_ eq '-f' } @$_ } @ran), 'clamscan gets the file list');

# --- uploader attribution: exactly one public IP POSTed to the site around the change time ---
my @t = gmtime($now);
my $ts = sprintf('%02d/%s/%04d:%02d:%02d:%02d +0000', $t[3], (qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec))[$t[4]], $t[5] + 1900, @t[2,1,0]);
put("$R/var/log/apache2/domlogs/bob.test",
    qq{198.51.100.7 - - [$ts] "POST /wp/upload.php HTTP/1.1" 200 12 "-" "x"\n},
    qq{127.0.0.1 - - [$ts] "POST /wp-cron.php HTTP/1.1" 200 1 "-" "x"\n},
    qq{203.0.113.9 - - [$ts] "GET / HTTP/1.1" 200 1 "-" "x"\n});
my ($ip, $how) = $sc->attribute("$docroot/wp/evil.php", $now);
is($ip, '198.51.100.7', 'single POSTing public IP is the uploader');
is($how, 'web', 'found in the web log');

put("$R/var/log/apache2/domlogs/bob.test-ssl_log", qq{192.0.2.44 - - [$ts] "POST /x HTTP/1.1" 200 1 "-" "x"\n});
my @amb = $sc->attribute("$docroot/wp/evil.php", $now);
is(scalar @amb, 0, 'two different POSTing IPs: ambiguous, no uploader');
unlink "$R/var/log/apache2/domlogs/bob.test-ssl_log";

# FTP log wins with the exact path
put("$R/var/log/xferlog", "Thu Nov  6 05:40:25 2026 0 192.0.2.99 1234 $docroot/wp/evil.php b _ i r bob ftp 0 * c\n");
($ip, $how) = $sc->attribute("$docroot/wp/evil.php", $now);
is_deeply([$ip, $how], ['192.0.2.99', 'ftp'], 'FTP upload with the exact path is attributed');
unlink "$R/var/log/xferlog";

# --- act: certain hit -> quarantine + block; heuristic -> report only ---
my $rep = $sc->act($hits);
my ($qa) = grep { $_->{file} =~ /evil\.php$/ } @$rep;
is($qa->{action}, 'quarantined', 'certain hit quarantined');
ok(!-e "$docroot/wp/evil.php", 'file removed from the site');
is($qa->{ip}, '198.51.100.7', 'uploader recorded');
is(scalar @blocked, 1, 'uploader blocked once');
is($blocked[0][1], 86400, 'temporary block, default 24 h');
SKIP: {
    skip 'antivirus blocks the malware samples', 1 if $av_blocked;
    my ($heur) = grep { $_->{file} =~ /shell\.php$/ } @$rep;
    is($heur->{action}, 'reported', 'heuristic hit only reported');
}
ok(-e "$docroot/wp/shell.php", 'heuristic hit left in place');
like(slurp("$R/var/log/csf2-scan.log"), qr/QUARANTINED .*evil\.php.*uploader=198\.51\.100\.7/, 'action logged');

# --- email alert: one message, only when something certain was found ---
make_path("$R/usr/sbin");
put("$R/usr/sbin/sendmail", "#!/bin/sh\ncat > '$R/mail.out'\n"); chmod 0755, "$R/usr/sbin/sendmail";
# hardened servers mount /tmp noexec: the fake sendmail cannot run there
my $can_exec = system("'$R/usr/sbin/sendmail' </dev/null >/dev/null 2>&1") == 0;
SKIP: { skip 'temp dir is mounted noexec - cannot run the fake sendmail', 5 unless $can_exec;
{ local $sc->{cfg}{SCAN_ALERT_TO} = 'admin@example.test';
  my ($sent, $to) = $sc->alert($rep);
  ok($sent, 'alert sent through sendmail') or diag $to;
  my $mail = slurp("$R/mail.out");
  like($mail, qr/^To: admin\@example\.test$/m, 'to SCAN_ALERT_TO');
  like($mail, qr/^Subject: \[CSF\] 1 malicious file\(s\) quarantined/m, 'subject counts quarantined files');
  like($mail, qr/csf --quarantine restore \d+-[0-9a-f]{4}/, 'restore command included');
  like($mail, qr/uploader:\s+198\.51\.100\.7/, 'uploader included'); }
}
{ unlink "$R/mail.out";
  my ($sent) = $sc->alert([ grep { !$_->{certain} } @$rep ]);
  ok(!$sent && !-e "$R/mail.out", 'heuristic-only run sends no email'); }
{ local $sc->{cfg}{SCAN_ALERT_TO} = 'none'; my ($sent, $why) = $sc->alert($rep); is($why, 'alerts disabled', 'SCAN_ALERT_TO=none disables'); }

# --- quarantine list / restore / delete ---
my @q = $sc->quarantine_list;
is(scalar @q, 1, 'one quarantine entry');
is($q[0]{path}, "$docroot/wp/evil.php", 'original path kept');
my ($ok, $msg) = $sc->quarantine_restore($q[0]{id});
ok($ok, 'restore works') or diag $msg;
like(slurp("$docroot/wp/evil.php"), qr/looks innocent/, 'content restored');
is(scalar($sc->quarantine_list), 0, 'entry gone after restore');
($ok) = $sc->quarantine_restore('../../etc');
ok(!$ok, 'invalid id refused');

# alert-only mode never touches files or blocks
{ local $sc->{cfg}{SCAN_ACTION} = 'alert'; local $sc->{cfg}{SCAN_BLOCK_UPLOADER} = 0; @blocked = ();
  my $r2 = $sc->act([{ file => "$docroot/wp/evil.php", engine => 'clamav', signature => 'X', certain => 1 }]);
  is($r2->[0]{action}, 'reported', 'SCAN_ACTION=alert only reports');
  ok(-e "$docroot/wp/evil.php", 'file untouched in alert mode');
  is(scalar @blocked, 0, 'no block with SCAN_BLOCK_UPLOADER=0'); }

# --- incremental run + Imunify360 coexistence ---
my $r = $sc->run_incremental;
ok(defined $r->{files}, 'incremental run completes');
ok(-s "$var/scan.last", 'last-run stamp written');
make_path("$R/usr/share/imunify360");
like($sc->run_incremental->{skipped} // '', qr/Imunify360/, 'skips when Imunify360 is present');
{ local $sc->{cfg}{SCAN_FORCE} = 1; ok(!$sc->run_incremental->{skipped}, 'SCAN_FORCE=1 overrides'); }

# --- other platforms ---
my $D = tempdir(CLEANUP => 1);
make_path("$D/usr/local/directadmin", "$D/home/ann/domains/ann.test/public_html");
is_deeply([ CSF2::Scanner->new(root => $D, var => "$D/v")->roots ], [ "$D/home/ann/domains/ann.test/public_html" ], 'DirectAdmin docroots');
my $C = tempdir(CLEANUP => 1);
make_path("$C/usr/bin", "$C/home/site1/htdocs/site1.test", "$C/home/clp/htdocs/app", "$C/home/csfui0a1b2c3d/htdocs/fw.test"); put("$C/usr/bin/clpctl", '');
is_deeply([ CSF2::Scanner->new(root => $C, var => "$C/v")->roots ], [ "$C/home/site1/htdocs/site1.test" ], 'CloudPanel docroots (panel app and UI proxy site skipped)');
my $G = tempdir(CLEANUP => 1);
make_path("$G/var/www/html", "$G/srv/app");
is_deeply([ CSF2::Scanner->new(root => $G, var => "$G/v", cfg => { SCAN_PATHS => '/srv/app' })->roots ],
          [ "$G/var/www", "$G/srv/app" ], 'no panel: /var/www plus SCAN_PATHS');

# --- an uploader is never blocked when it is trusted ---
require CSF2::State;
my $T = tempdir(CLEANUP => 1);
make_path("$T/etc", "$T/v", "$T/var/log");
put("$T/etc/csf.allow", "203.0.113.10 # office\n");
put("$T/etc/csf.ignore", "192.0.2.0/24 # monitoring\n");
put("$T/var/log/csf2-ui.log", "2026-11-06 18:57:24 csf2-ui: login ok for user admin from 198.51.100.7\n");
my $ts = CSF2::Scanner->new(root => $T, var => "$T/v", engine => { state => CSF2::State->new(etc => "$T/etc", var => "$T/v") });
is($ts->trusted_ip('203.0.113.10'), 'allow list', 'allow-listed uploader is not blocked');
is($ts->trusted_ip('192.0.2.44'), 'csf.ignore', 'csf.ignore uploader is not blocked');
is($ts->trusted_ip('198.51.100.7'), 'CSF administrator', 'an admin who signed in to the web UI is not blocked');
is($ts->trusted_ip('203.0.113.99'), '', 'anyone else can be blocked');

done_testing;
