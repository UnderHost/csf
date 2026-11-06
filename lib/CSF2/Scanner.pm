package CSF2::Scanner;

###############################################################################
# CSF 2.3 - Core Shield Firewall
# CSF2::Scanner - malicious upload scanning for website files.
#
# Every few minutes (cron, `csf --scan`) the files created or changed since
# the last run under the websites' document roots are scanned with:
#   - ClamAV + the rfxn (Linux Malware Detect) web-malware signatures
#   - YARA: rfxn.yara + YARA-Forge core rules (compiled at --scan-update)
#   - a few built-in heuristics (obfuscated eval, known web-shell markers)
# Engine hits on web-malware signatures are "certain": the file is moved to
# quarantine (restorable) and the uploader's IP - found in the FTP or web log
# around the upload time, and only when it is unambiguous - gets a temporary
# block. Heuristic-only hits are reported, never acted on.
#
# Paths are rooted (root => '/tmp/fixture') and commands go through an
# injectable runner, so everything is unit-testable without real engines.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use File::Find ();
use File::Copy ();
use File::Path ();
use File::Basename ();
use Fcntl qw(O_RDONLY O_WRONLY O_CREAT O_EXCL O_NOFOLLOW);
use POSIX ();
use Time::Local ();
use CSF2::Platform;

our @DEFAULT_EXT = qw(php php3 php4 php5 php7 php8 phtml phar inc pl py cgi sh
                      js html htm shtml ico suspected);
our $LOG_TAIL = 20 * 1024 * 1024;    # bytes of each log searched for the uploader

# Built-in heuristics: report only (never quarantine or block on these alone).
our @HEURISTICS = (
    ['CSF.Heur.Eval.Decode',  qr/\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev|rawurldecode)\s*\(/i],
    ['CSF.Heur.Eval.Input',   qr/\b(?:eval|assert|create_function)\s*\(\s*(?:stripslashes\s*\(\s*)?\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b/i],
    ['CSF.Heur.PregE',        qr/preg_replace\s*\(\s*['"][^'"]{1,80}\/[a-z]*e[a-z]*['"]\s*,/i],
    ['CSF.Heur.WebShell',     qr/(?:FilesMan|b374k|c99shell|r57shell|IndoXploit|WSO\s+[0-9.]+|Uname:\s*<\/?\w)/],
    ['CSF.Heur.PHPinImage',   qr/<\?php/i, qr/\.(?:ico|png|jpe?g|gif)$/i],
);

# YARA rule names that are about web malware: these count as certain.
our $YARA_WEB = qr/webshell|web_shell|php|jsp|aspx?\b|phish|backdoor|skimmer|magecart|cryptominer|coinminer|injector|dropper|rfxn|maldet/i;

sub new {
    my ($class, %a) = @_;
    my $self = {
        cfg      => $a{cfg} || {},
        root     => defined $a{root} ? $a{root} : '',
        var      => $a{var} || '/var/lib/csf',
        engine   => $a{engine},                          # CSF2::Engine (blocking), optional
        run      => $a{run} || \&_run_cmd,               # ($argv_aref) -> output text
        now      => $a{now} || sub { time },
        log      => $a{log} || '/var/log/csf2-scan.log',
        platform => $a{platform},
    };
    bless $self, $class;
    $self->{platform} ||= CSF2::Platform->new(root => $self->{root})->detect;
    return $self;
}

sub _p     { my ($s, $rel) = @_; return $s->{root} . $rel }
sub cfg    { my ($s, $k, $d) = @_; my $v = $s->{cfg}{$k}; return (defined $v && $v ne '') ? $v : $d }
sub sigdir { my $s = shift; return "$s->{var}/sigs" }
sub qdir   { my $s = shift; return "$s->{var}/quarantine" }

sub _run_cmd {
    my ($argv) = @_;
    my $cmd = join ' ', map { my $x = $_; $x =~ s/'/'\\''/g; "'$x'" } @$argv;
    return scalar `$cmd 2>/dev/null`;
}

###############################################################################
# Imunify360 already scans uploads: running both doubles the work and fights
# over quarantined files. The scanner stays off there unless SCAN_FORCE=1.
sub imunify_present {
    my $s = shift;
    return (-e $s->_p('/usr/bin/imunify360-agent') || -d $s->_p('/usr/share/imunify360')) ? 1 : 0;
}

###############################################################################
# Document roots per platform (plus SCAN_PATHS), existing directories only.
sub roots {
    my $s = shift;
    my @r;
    my $plat = $s->{platform};
    if ($plat eq 'cpanel') {
        push @r, map { $_->[0] } $s->_cpanel_docroots;
        push @r, glob($s->_p('/home/*/public_html')) unless @r;
    } elsif ($plat eq 'directadmin') {
        push @r, glob($s->_p('/home/*/domains/*/public_html'));
    } elsif ($plat eq 'cloudpanel') {
        # skip CloudPanel's own app (clp) and the csf2-ui proxy site (csfui*)
        push @r, grep { !m{/home/(?:clp|csfui[0-9a-f]*)/htdocs/} } glob($s->_p('/home/*/htdocs/*'));
    } else {
        push @r, $s->_p('/var/www');
    }
    for my $extra (split /\s*,\s*/, $s->cfg('SCAN_PATHS', '')) {
        next unless length $extra && $extra =~ m{^/};
        push @r, glob($s->_p($extra));
    }
    my %seen;
    @r = grep { -d $_ && !-l $_ && !$seen{$_}++ } @r;
    # an addon domain's docroot often lives inside another site's: scan it once
    my @top;
    for my $d (sort { length($a) <=> length($b) } @r) {
        push @top, $d unless grep { index($d, "$_/") == 0 } @top;
    }
    my %keep = map { $_ => 1 } @top;
    return grep { $keep{$_} } @r;
}

# cPanel: /etc/userdatadomains  "domain: user==owner==type==main==docroot==..."
# -> ([docroot, domain], ...) longest docroot first
sub _cpanel_docroots {
    my $s = shift;
    my $f = $s->_p('/etc/userdatadomains');
    my @d;
    if (open my $fh, '<', $f) {
        while (my $l = <$fh>) {
            chomp $l;
            my ($dom, $rest) = split /:\s+/, $l, 2;
            next unless defined $rest;
            my @f = split /==/, $rest;
            next unless $f[4] && $f[4] =~ m{^/};
            push @d, [$s->_p($f[4]), $dom];
        }
        close $fh;
    }
    return sort { length($b->[0]) <=> length($a->[0]) } @d;
}

###############################################################################
# candidates($since) -> (\@files, $truncated)
# Regular files changed (mtime or ctime) after $since, with a scanned
# extension, under the size limit. Symlinks are never followed or scanned.
sub candidates {
    my ($s, $since, @paths) = @_;
    @paths = $s->roots unless @paths;
    my $max   = $s->cfg('SCAN_MAX_SIZE', 5 * 1024 * 1024);
    my $limit = $s->cfg('SCAN_MAX_FILES', 20000);
    my $all   = ($s->cfg('SCAN_EXT', '') eq '*');
    my %ext   = map { lc($_) => 1 } ($s->cfg('SCAN_EXT', '') && !$all ? split(/\s*,\s*/, $s->cfg('SCAN_EXT')) : @DEFAULT_EXT);
    my @excl  = map { $s->_p($_) } grep { m{^/} } split /\s*,\s*/, $s->cfg('SCAN_EXCLUDE', '');
    my $q     = $s->qdir;
    my @found;                                   # [changed, path]
    my @odd;                                     # names with control characters
    File::Find::find({
        no_chdir => 1,
        wanted   => sub {
            my $f = $File::Find::name;
            # a line break would split the engines' file list: never scan such a
            # name, report it (nothing legitimate needs one)
            if ($f =~ /[\x00-\x1f\x7f]/) { push @odd, $f; return }
            if (-d $f) {
                if (-l $f || $f eq $q || grep { $f eq $_ || index($f, "$_/") == 0 } @excl) { $File::Find::prune = 1 }
                elsif ($f =~ m{/(?:\.git|node_modules)$}) { $File::Find::prune = 1 }
                return;
            }
            my @st = lstat $f or return;
            return unless -f _;
            return if $st[7] > $max || $st[7] == 0;
            my $changed = $st[9] > $st[10] ? $st[9] : $st[10];
            return unless $changed > $since;
            unless ($all) {
                my ($e) = $f =~ /\.([^.\/]+)$/;
                return unless defined $e && $ext{lc $e};
            }
            push @found, [$changed, $f];
        },
    }, grep { -d $_ } @paths);
    for my $o (@odd) { (my $show = $o) =~ s/[\x00-\x1f\x7f]/?/g; $s->_log("SUSPICIOUS file name with control characters, not scanned: $show") }
    # Oldest change first: when the per-run limit cuts the list, the next run
    # continues from the last file scanned (third return value) - nothing is skipped.
    @found = sort { $a->[0] <=> $b->[0] || $a->[1] cmp $b->[1] } @found;
    my $trunc = @found > $limit ? 1 : 0;
    splice @found, $limit if $trunc;
    return ([ map { $_->[1] } @found ], $trunc, ($trunc ? $found[-1][0] : undef));
}

###############################################################################
# Engines
sub clamscan_bin {
    my $s = shift;
    for my $b ('/usr/bin/clamscan', '/usr/local/cpanel/3rdparty/bin/clamscan', '/usr/local/bin/clamscan') {
        return $b if -x $s->_p($b);
    }
    return undef;
}
sub yara_bin {
    my $s = shift;
    for my $b ('/usr/bin/yara', '/usr/local/bin/yara') { return $b if -x $s->_p($b) }
    return undef;
}
sub clam_dbs {
    my $s = shift;
    my @db = grep { -s $_ } map { $s->sigdir . "/$_" } qw(rfxn.ndb rfxn.hdb);
    push @db, $s->_p('/var/lib/clamav') if $s->cfg('SCAN_CLAMAV_OFFICIAL', 0) && -d $s->_p('/var/lib/clamav');
    return @db;
}
sub yara_rules { my $s = shift; my $f = $s->sigdir . '/csf-rules.yarc'; return -s $f ? $f : undef }

# engines() -> { clamav => bool, yara => bool, heuristics => 1 }
sub engines {
    my $s = shift;
    return {
        clamav     => ($s->clamscan_bin && $s->clam_dbs) ? 1 : 0,
        yara       => ($s->yara_bin && $s->yara_rules) ? 1 : 0,
        heuristics => 1,
    };
}

# scan(\@files) -> [ { file, engine, signature, certain }, ... ] (one per file, strongest kept)
sub scan {
    my ($s, $files) = @_;
    return [] unless @$files;
    my %hit;
    my %listed = map { $_ => 1 } @$files;
    my $keep = sub {
        my ($h) = @_;
        return unless $listed{ $h->{file} };     # only files we asked about
        my $cur = $hit{ $h->{file} };
        $hit{ $h->{file} } = $h if !$cur || ($h->{certain} && !$cur->{certain});
    };

    my $list = "$s->{var}/scan-list.$$";
    if (open my $fh, '>', $list) { print {$fh} "$_\n" for @$files; close $fh }

    if (my $clam = $s->clamscan_bin) {
        if (my @db = $s->clam_dbs) {
            my $out = $s->{run}->([$clam, '--no-summary', '--infected', '--stdout',
                                   '--max-filesize=' . $s->cfg('SCAN_MAX_SIZE', 5 * 1024 * 1024),
                                   (map { ('-d', $_) } @db), '-f', $list]);
            for my $l (split /\n/, $out // '') {
                next unless $l =~ /^(.+?): (\S+) FOUND$/;
                $keep->({ file => $1, engine => 'clamav', signature => $2, certain => 1 });
            }
        }
    }
    if (my $yara = $s->yara_bin) {
        if (my $rules = $s->yara_rules) {
            my $out = $s->{run}->([$yara, '-C', '--fast-scan', '--scan-list', $rules, $list]);
            for my $l (split /\n/, $out // '') {
                next unless $l =~ /^(\S+)\s+(\/.+)$/;
                my ($rule, $f) = ($1, $2);
                $keep->({ file => $f, engine => 'yara', signature => $rule, certain => ($rule =~ $YARA_WEB ? 1 : 0) });
            }
        }
    }
    unlink $list;

    for my $f (@$files) {
        next if $hit{$f} && $hit{$f}{certain};
        my $sig = $s->heuristic($f) or next;
        $keep->({ file => $f, engine => 'heuristic', signature => $sig, certain => 0 });
    }
    return [ map { $hit{$_} } sort keys %hit ];
}

# heuristic($file) -> signature name | undef  (first 512 KB)
sub heuristic {
    my ($s, $f) = @_;
    open my $fh, '<', $f or return undef;
    binmode $fh;
    my $buf = '';
    read($fh, $buf, 512 * 1024);
    close $fh;
    for my $h (@HEURISTICS) {
        my ($name, $re, $only) = @$h;
        next if $only && $f !~ $only;
        return $name if $buf =~ $re;
    }
    return undef;
}

###############################################################################
# Quarantine: the file is moved to $var/quarantine/<id>/ (mode 000, root-only
# directory) with a meta file, so it can be restored exactly as it was.
sub quarantine {
    my ($s, $hit) = @_;
    my $f = $hit->{file};
    # The site owner controls this path: never follow a symlink swapped in after
    # the scan, copy from the opened file, and remove the path only if it is
    # still that same file.
    sysopen(my $in, $f, O_RDONLY | O_NOFOLLOW) or return (0, "cannot open $f safely: $!");
    my @st = stat $in;
    return (0, "$f is not a regular file") unless @st && -f _;
    my $id = sprintf('%d-%04x', $s->{now}->(), int(rand(0xffff)));
    my $d  = $s->qdir . "/$id";
    File::Path::make_path($d, { mode => 0700 });
    chmod 0700, $s->qdir;
    open(my $out, '>', "$d/file") or return (0, "copy failed: $!");
    binmode $in; binmode $out;
    File::Copy::copy($in, $out) or return (0, "copy failed: $!");
    close $out; close $in;
    return (0, 'copy size mismatch') unless -s "$d/file" == $st[7];
    my @now = lstat $f;
    unless (@now && -f _ && $now[0] == $st[0] && $now[1] == $st[1]) {
        File::Path::remove_tree($d);
        return (0, "$f changed while it was being quarantined - left in place");
    }
    unlink $f or do { unlink "$d/file"; return (0, "cannot remove $f: $!") };
    chmod 0000, "$d/file";
    if (open my $m, '>', "$d/meta") {
        printf {$m} "path=%s\nmode=%o\nuid=%d\ngid=%d\nmtime=%d\nsize=%d\nengine=%s\nsignature=%s\ntime=%d\nip=%s\n",
            $f, $st[2] & 07777, $st[4], $st[5], $st[9], $st[7], $hit->{engine}, $hit->{signature}, $s->{now}->(), ($hit->{ip} // '');
        close $m;
    }
    return (1, $id);
}

sub quarantine_list {
    my $s = shift;
    my @out;
    for my $d (sort glob($s->qdir . '/*')) {
        my %m = _read_meta("$d/meta") or next;
        my ($id) = $d =~ m{/([^/]+)$};
        push @out, { id => $id, %m };
    }
    return @out;
}

sub quarantine_restore {
    my ($s, $id) = @_;
    return (0, 'invalid id') unless defined $id && $id =~ /^\d+-[0-9a-f]{4}$/;
    my $d = $s->qdir . "/$id";
    my %m = _read_meta("$d/meta") or return (0, "no quarantine entry $id");
    my $path = $m{path} // '';
    my ($uid, $gid) = map { defined $_ && /^\d+$/ ? $_ : -1 } @m{qw(uid gid)};
    return (0, 'invalid quarantine entry') unless $path =~ m{^/} && $path !~ /[\x00-\x1f\x7f]/ && $uid >= 0 && $gid >= 0;
    return (0, "$path exists again - not overwriting it") if -e $path || -l $path;
    # The folders on the way belong to the site owner. Never write through a
    # symlink, and write as the file's owner, never as root: a folder swapped for
    # a link to /etc must not turn a restore into a root file write.
    my $why = _unsafe_parents($path, $uid);
    return (0, "not restored: $why - restore it by hand after checking the folder") if $why;
    chmod 0600, "$d/file";
    open(my $in, '<', "$d/file") or return (0, "cannot read quarantine entry $id: $!");
    binmode $in;
    my $mode = (($m{mode} // '') =~ /^[0-7]{1,4}$/) ? oct($m{mode}) & 0777 : 0644;
    my $pid = fork();
    return (0, "restore failed: cannot fork: $!") unless defined $pid;
    if (!$pid) {
        if ($> == 0 && $uid != 0) {          # drop to the owner (and its group) for the write
            $) = "$gid $gid"; $( = $gid; POSIX::setgid($gid);
            POSIX::setuid($uid);
            POSIX::_exit(3) unless $> == $uid && $< == $uid;
        }
        sysopen(my $out, $path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600) or POSIX::_exit(4);
        binmode $out;
        File::Copy::copy($in, $out) or POSIX::_exit(5);
        close $out or POSIX::_exit(5);
        chmod $mode, $path;
        utime $m{mtime}, $m{mtime}, $path if ($m{mtime} // '') =~ /^\d+$/;
        POSIX::_exit(0);
    }
    waitpid($pid, 0);
    my $rc = $? >> 8;
    close $in;
    return (0, "restore failed (" . ({ 3 => 'cannot switch to the file owner', 4 => 'cannot create the file safely',
                                      5 => 'write error' }->{$rc} || "code $rc") . ')') if $rc;
    File::Path::remove_tree($d);
    return (1, "restored $path");
}

# _unsafe_parents($path, $uid) -> reason | ''   No folder on the way may be a
# symlink; for a root-owned file every folder must also be root-owned and not
# writable by others, since the write then cannot drop privileges.
sub _unsafe_parents {
    my ($path, $uid) = @_;
    my $dir = File::Basename::dirname($path);
    my @parts = grep { length } split m{/}, $dir;
    my $cur = '';
    for my $p (@parts) {
        $cur .= "/$p";
        my @st = lstat $cur or return "$cur is missing";
        return "$cur is a symbolic link" if -l _;
        return "$cur is not a folder" unless -d _;
        if ($uid == 0 && $> == 0) {
            return "$cur is not owned by root" if $st[4] != 0;
            # world-writable is fine only with the sticky bit (like /tmp):
            # nobody can then rename or replace an entry they do not own
            return "$cur is writable by other users" if ($st[2] & 0022) && !($st[2] & 01000);
        }
    }
    return '';
}

sub quarantine_delete {
    my ($s, $id) = @_;
    return (0, 'invalid id') unless defined $id && $id =~ /^\d+-[0-9a-f]{4}$/;
    my $d = $s->qdir . "/$id";
    return (0, "no quarantine entry $id") unless -d $d;
    File::Path::remove_tree($d);
    return (1, "deleted quarantine entry $id");
}

sub _read_meta {
    my $f = shift;
    open my $fh, '<', $f or return;
    my %m = map { chomp; split /=/, $_, 2 } grep { /=/ } <$fh>;
    close $fh;
    return %m;
}

###############################################################################
# Uploader attribution. FTP logs name the exact path (strong). Web logs only
# give POST requests to the site around the change time: used only when a
# single public IP posted in that window. Returns (ip, method) or ().
sub attribute {
    my ($s, $file, $when) = @_;
    my $win = $s->cfg('SCAN_ATTRIB_WINDOW', 120);

    # FTP: xferlog "Thu Nov  6 05:40:25 2026 0 1.2.3.4 1234 /path b _ i r user ftp 0 * c"
    #      pure-ftpd syslog "pure-ftpd: (user@1.2.3.4) [NOTICE] /path uploaded"
    for my $log ('/var/log/xferlog', '/var/log/messages', '/var/log/pureftpd.log', '/var/log/proftpd/xferlog') {
        my $ip;
        for my $l (_tail_lines($s->_p($log))) {
            next unless index($l, $file) >= 0;
            if ($l =~ /^\w{3} \w{3}\s+\d+ [\d:]+ \d{4} \d+ (\S+) \d+ (\S+) /) { $ip = $1 if $2 eq $file }
            elsif ($l =~ /\(\S*?@(\S+?)\)\s+\[\w+\]\s+(\S+) uploaded/) { $ip = $1 if $2 eq $file }
        }
        return ($ip, 'ftp') if $ip && _public_ip($ip);
    }

    # Web: POSTs to this site's access log(s) within +/- window
    my %ips;
    for my $log ($s->_web_logs($file)) {
        for my $l (_tail_lines($log)) {
            next unless $l =~ /^(\S+) \S+ \S+ \[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\] "POST /;
            my ($ip, $t) = ($1, _clf_time($2, $3, $4, $5, $6, $7, $8));
            next unless defined $t && abs($t - $when) <= $win && _public_ip($ip);
            $ips{$ip}++;
        }
    }
    return (keys(%ips) == 1) ? ((keys %ips)[0], 'web') : ();
}

sub _web_logs {
    my ($s, $file) = @_;
    my $plat = $s->{platform};
    my @g;
    if ($plat eq 'cpanel') {
        for my $d ($s->_cpanel_docroots) {
            next unless index($file, "$d->[0]/") == 0;
            push @g, map { ("$_/$d->[1]", "$_/$d->[1]-ssl_log") }
                     ('/var/log/apache2/domlogs', '/usr/local/apache/domlogs', '/etc/apache2/logs/domlogs');
            last;
        }
    } elsif ($plat eq 'directadmin') {
        my ($dom) = $file =~ m{/home/[^/]+/domains/([^/]+)/};
        push @g, "/var/log/httpd/domains/$dom.log" if $dom;
    } elsif ($plat eq 'cloudpanel') {
        my ($u) = $file =~ m{/home/([^/]+)/htdocs/};
        push @g, "/home/$u/logs/nginx/access.log" if $u;
    }
    push @g, '/var/log/nginx/access.log', '/var/log/apache2/access.log', '/var/log/httpd/access_log' unless @g;
    return grep { -f $_ } map { $s->_p($_) } @g;
}

my %MON = (Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11);
sub _clf_time {
    my ($d, $mon, $y, $h, $mi, $sec, $tz) = @_;
    return undef unless exists $MON{$mon};
    my $t = eval { Time::Local::timegm($sec, $mi, $h, $d, $MON{$mon}, $y) };
    return undef unless defined $t;
    my ($sign, $th, $tm) = $tz =~ /([+-])(\d\d)(\d\d)/;
    my $off = ($th * 3600 + $tm * 60) * ($sign eq '-' ? -1 : 1);
    return $t - $off;
}

sub _public_ip {
    my $ip = shift;
    return 0 unless defined $ip;
    return 0 if $ip =~ /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|::1$|fe80:|fc|fd)/i;
    return ($ip =~ /^[\d.]+$/ || $ip =~ /^[0-9a-f:]+$/i) ? 1 : 0;
}

sub _tail_lines {
    my $f = shift;
    open my $fh, '<', $f or return ();
    my $size = -s $fh;
    if ($size > $LOG_TAIL) { seek $fh, $size - $LOG_TAIL, 0; <$fh> }   # drop the partial first line
    my @l = <$fh>;
    close $fh;
    chomp @l;
    return @l;
}

###############################################################################
# trusted_ip($ip) -> reason | ''  - an uploader we must never block: the allow
# list, csf.ignore, or an administrator who signed in to the CSF web interface
# (on a server without a panel its sign-ins share the nginx log with the sites).
sub trusted_ip {
    my ($s, $ip) = @_;
    require CSF2::IP;
    my $c = CSF2::IP::normalize($ip) // return '';
    my $state = $s->{engine} ? $s->{engine}{state} : undef;
    if ($state) {
        my @allow = map { $_->{canonical} } @{ $state->load_list('allow') };
        return 'allow list' if CSF2::IP::ip_in_any($c, \@allow);
        my $ign = "$state->{etc}/csf.ignore";
        if (open my $fh, '<', $ign) {
            my @ig = grep { length } map { s/\s*#.*//; s/^\s+|\s+$//g; $_ } <$fh>;
            close $fh;
            return 'csf.ignore' if CSF2::IP::ip_in_any($c, \@ig);
        }
    }
    for my $l (_tail_lines($s->_p('/var/log/csf2-ui.log'))) {
        return 'CSF administrator' if $l =~ /login ok for user \S+ from (\S+)/ && (CSF2::IP::normalize($1) // '') eq $c;
    }
    return '';
}

###############################################################################
# act(\@hits) -> report. Certain hits are quarantined (SCAN_ACTION=quarantine)
# and their uploader blocked (SCAN_BLOCK_UPLOADER); everything is logged.
sub act {
    my ($s, $hits) = @_;
    my $quar  = $s->cfg('SCAN_ACTION', 'quarantine') eq 'quarantine';
    my $block = $s->cfg('SCAN_BLOCK_UPLOADER', 1);
    my $ttl   = $s->cfg('SCAN_BLOCK_TTL', 86400);
    my @rep;
    for my $h (@$hits) {
        my @st = lstat $h->{file};
        my $when = @st ? ($st[9] > $st[10] ? $st[9] : $st[10]) : $s->{now}->();
        my %r = (%$h, action => 'reported');
        if ($h->{certain}) {
            my ($ip, $how) = $s->attribute($h->{file}, $when);
            $h->{ip} = $ip if $ip;
            if ($quar) {
                my ($ok, $id) = $s->quarantine($h);
                %r = (%r, action => $ok ? 'quarantined' : 'quarantine FAILED', id => $ok ? $id : undef, error => $ok ? undef : $id);
            }
            my $trust = $ip ? $s->trusted_ip($ip) : '';
            if ($ip && $trust) {
                %r = (%r, ip => $ip, ip_from => $how, blocked => 0, not_blocked => $trust);
            } elsif ($ip && $block && $s->{engine}) {
                # the file name is chosen by the uploader: printable, no markup, bounded
                (my $what = "$h->{file} ($h->{signature})") =~ s/[^\x20-\x7e]|[<>"'&`]/?/g;
                my ($ok) = $s->{engine}->tempdeny($ip, $ttl, comment => 'Scanner: uploaded ' . substr($what, 0, 200));
                %r = (%r, ip => $ip, ip_from => $how, blocked => $ok ? 1 : 0);
            } elsif ($ip) {
                %r = (%r, ip => $ip, ip_from => $how, blocked => 0);
            }
        }
        $s->_log(sprintf '%s %s [%s %s]%s%s', uc($r{action}), $h->{file}, $h->{engine}, $h->{signature},
                 ($r{id} ? " id=$r{id}" : ''), ($r{ip} ? " uploader=$r{ip} ($r{ip_from})"
                     . ($r{blocked} ? ' blocked' : $r{not_blocked} ? " not blocked: $r{not_blocked}" : '') : ''));
        push @rep, \%r;
    }
    return \@rep;
}

###############################################################################
# alert(\@report) -> (sent?, recipient|reason)
# One email per run when something certain was found (heuristic-only runs only
# go to the log). To: SCAN_ALERT_TO, else LF_ALERT_TO, else root; "none" = off.
sub alert {
    my ($s, $rep) = @_;
    my @certain = grep { $_->{certain} } @$rep;
    return (0, 'nothing certain to report') unless @certain;
    my $to = $s->cfg('SCAN_ALERT_TO', '') || $s->cfg('LF_ALERT_TO', '') || 'root';
    return (0, 'alerts disabled') if lc($to) eq 'none';
    return (0, 'invalid recipient') unless $to =~ /^[A-Za-z0-9._%+\-@, ]+$/;
    my ($sm) = grep { -x $s->_p($_) } ('/usr/sbin/sendmail', '/usr/lib/sendmail');
    return (0, 'no sendmail on this server') unless $sm;
    chomp(my $host = `hostname -f 2>/dev/null` || 'server');
    my $from = $s->cfg('SCAN_ALERT_FROM', '') || $s->cfg('LF_ALERT_FROM', '') || "csf\@$host";
    my $q = grep { $_->{action} eq 'quarantined' } @certain;
    my $body = "CSF (Core Shield Firewall) found malicious files on $host.\n\n";
    for my $r (@$rep) {
        $body .= sprintf "%s\n  file:      %s\n  signature: %s (%s)\n%s%s\n",
            uc $r->{action}, $r->{file}, $r->{signature}, $r->{engine},
            ($r->{id} ? "  restore:   csf --quarantine restore $r->{id}\n" : ''),
            ($r->{ip} ? "  uploader:  $r->{ip} (from the $r->{ip_from} log)" . ($r->{blocked} ? ', blocked for ' . int($s->cfg('SCAN_BLOCK_TTL', 86400) / 3600) . " h\n" : "\n") : '');
    }
    $body .= "Heuristic findings (if any) were only logged, not changed.\n"
           . "Quarantined files can be restored with the command shown, or from the Malware Scan tab.\n"
           . "Log: /var/log/csf2-scan.log\n";
    my $subj = $q ? "[CSF] $q malicious file(s) quarantined on $host" : "[CSF] " . scalar(@certain) . " malicious file(s) found on $host";
    open my $mh, '|-', $s->_p($sm), '-t', '-oi' or return (0, 'sendmail failed');
    print {$mh} "To: $to\nFrom: $from\nSubject: $subj\nContent-Type: text/plain; charset=UTF-8\n\n$body";
    close $mh;
    return ($? == 0 ? 1 : 0, $to);
}

sub _log {
    my ($s, $msg) = @_;
    my @t = gmtime($s->{now}->());
    if (open my $fh, '>>', $s->_p($s->{log})) {
        printf {$fh} "%04d-%02d-%02d %02d:%02d:%02d UTC %s\n", $t[5] + 1900, $t[4] + 1, @t[3, 2, 1, 0], $msg;
        close $fh;
    }
}

###############################################################################
# Signatures. Sources (all free, reputable, HTTPS):
#   rfxn / Linux Malware Detect: ClamAV-format web-malware sigs + rfxn.yara
#   YARA-Forge core rule set (curated, deduplicated public YARA rules)
#   ClamAV official databases via freshclam, only when SCAN_CLAMAV_OFFICIAL=1
# Each download goes to a temp dir, is checked with the engine, and only then
# replaces the working copy - a broken download never removes working sigs.
our $RFXN_PACK = 'https://cdn.rfxn.com/downloads/maldet-sigpack.tgz';
our $RFXN_VER  = 'https://cdn.rfxn.com/downloads/maldet.sigs.ver';
our $YARAFORGE = 'https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip';

sub update_signatures {
    my $s = shift;
    my %rep;
    my $sig = $s->sigdir;
    File::Path::make_path($sig, { mode => 0700 });
    my $tmp = "$s->{var}/sig-update.$$";
    File::Path::remove_tree($tmp);
    File::Path::make_path($tmp, { mode => 0700 });
    my $curl = -x '/usr/bin/curl' ? '/usr/bin/curl' : 'curl';
    my $get  = sub { my ($url, $out) = @_; return system($curl, '-fsSL', '--max-time', '300', '-o', $out, $url) == 0 && -s $out };

    # rfxn
    if ($get->($RFXN_PACK, "$tmp/sigpack.tgz") && system('tar', 'xzf', "$tmp/sigpack.tgz", '-C', $tmp) == 0) {
        my @need = grep { -s "$tmp/sigs/$_" } qw(rfxn.ndb rfxn.hdb);
        my $clam = $s->clamscan_bin;
        # load the new signatures once against an empty file: exit 0 = they parse
        _write("$tmp/empty.txt", '');
        my $valid = @need == 2 && (!$clam || system("$clam --no-summary " . join(' ', map { "-d '$tmp/sigs/$_'" } @need) . " '$tmp/empty.txt' >/dev/null 2>&1") == 0);
        if ($valid) {
            File::Copy::move("$tmp/sigs/$_", "$sig/$_") for @need, grep { -s "$tmp/sigs/$_" } qw(rfxn.yara);
            my ($ver) = (`$curl -fsSL --max-time 30 $RFXN_VER 2>/dev/null` // '') =~ /(\d+)/;
            _write("$sig/rfxn.ver", $ver // 'unknown');
            $rep{rfxn} = 'ok' . ($ver ? " ($ver)" : '');
        } else { $rep{rfxn} = 'FAILED: signature pack did not validate' }
    } else { $rep{rfxn} = 'FAILED: download' }

    # YARA-Forge core
    if ($get->($YARAFORGE, "$tmp/yf.zip")) {
        require IO::Uncompress::Unzip;
        my $ok = IO::Uncompress::Unzip::unzip("$tmp/yf.zip" => "$tmp/yara-forge-core.yar",
                    Name => 'packages/core/yara-rules-core.yar', BinModeOut => 1);
        if ($ok && -s "$tmp/yara-forge-core.yar") {
            File::Copy::move("$tmp/yara-forge-core.yar", "$sig/yara-forge-core.yar");
            $rep{yaraforge} = 'ok';
        } else { $rep{yaraforge} = 'FAILED: unzip' }
    } else { $rep{yaraforge} = 'FAILED: download' }

    # compile all YARA sources into one rule file for fast scans
    my ($yarac) = grep { -x $_ } ('/usr/bin/yarac', '/usr/local/bin/yarac');
    if ($yarac) {
        # each source in its own namespace (rule names repeat across sets)
        my @have = grep { -s $_->[1] } (['rfxn', "$sig/rfxn.yara"], ['yaraforge', "$sig/yara-forge-core.yar"]);
        my @src = map { $_->[0] . ':' . $_->[1] } @have;
        my $built;
        # all sources together; if one does not compile with this YARA build, keep
        # the others; YARA < 4.2 has no "namespace:file", so last try each file plain
        for my $set ([@src], (map { [$_] } reverse @src), (map { [$_->[1]] } @have)) {
            next unless @$set;
            if (system("$yarac -w " . join(' ', map { "'$_'" } @$set) . " '$tmp/rules.yarc' >/dev/null 2>&1") == 0 && -s "$tmp/rules.yarc") {
                File::Copy::move("$tmp/rules.yarc", "$sig/csf-rules.yarc");
                $built = join(' + ', map { (split m{/}, $_)[-1] } @$set);
                last;
            }
        }
        $rep{yara_compile} = $built ? "ok ($built)" : 'FAILED: no rule set compiled';
    } else { $rep{yara_compile} = 'skipped: yarac not installed' }

    if ($s->cfg('SCAN_CLAMAV_OFFICIAL', 0)) {
        my ($fc) = grep { -x $_ } ('/usr/bin/freshclam', '/usr/local/cpanel/3rdparty/bin/freshclam');
        $rep{clamav_official} = $fc ? (system("$fc --quiet >/dev/null 2>&1") == 0 ? 'ok' : 'FAILED: freshclam') : 'skipped: freshclam not installed';
    }
    File::Path::remove_tree($tmp);
    _write("$sig/updated", $s->{now}->());
    return \%rep;
}

sub _write { my ($f, $c) = @_; if (open my $fh, '>', $f) { print {$fh} "$c\n"; close $fh } }

# status() -> hash for `csf --scan-status` and the self-test
sub status {
    my $s = shift;
    my $rd = sub { my $f = shift; open my $fh, '<', $f or return undef; my $l = <$fh>; close $fh; chomp $l if defined $l; return $l };
    return {
        enabled   => $s->cfg('SCAN_ENABLE', 0) ? 1 : 0,
        engines   => $s->engines,
        imunify   => $s->imunify_present,
        last_run  => $rd->("$s->{var}/scan.last"),
        sigs_at   => $rd->($s->sigdir . '/updated'),
        rfxn_ver  => $rd->($s->sigdir . '/rfxn.ver'),
        quarantine=> scalar($s->quarantine_list),
        roots     => [ $s->roots ],
        clamscan  => $s->clamscan_bin,
        yara      => $s->yara_bin,
    };
}

###############################################################################
# run_incremental() -> { files, truncated, hits => [...], since } | { skipped => reason }
# Scans what changed since the previous run (first run: the last hour).
sub run_incremental {
    my $s = shift;
    return { skipped => 'Imunify360 is installed (set SCAN_FORCE=1 to scan anyway)' }
        if $s->imunify_present && !$s->cfg('SCAN_FORCE', 0);
    my $stamp = "$s->{var}/scan.last";
    my $now   = $s->{now}->();
    my $since = $now - 3600;
    if (-s $stamp && open(my $fh, '<', $stamp)) { my $l = <$fh>; close $fh; $since = $1 if defined $l && $l =~ /(\d+)/ }
    my ($files, $trunc, $upto) = $s->candidates($since - 60);   # small overlap: never miss a file
    my $hits = $s->scan($files);
    my $rep  = $s->act($hits);
    $s->alert($rep);
    my $next = $trunc ? $upto : $now;
    if (open my $w, '>', $stamp) { print {$w} "$next\n"; close $w }
    $s->_log(sprintf 'run: %d file(s) changed since %d, %d hit(s)%s', scalar @$files, $since, scalar @$rep,
             $trunc ? ' (file limit reached, rest next run)' : '') if @$files || @$rep;
    return { files => scalar @$files, truncated => $trunc, hits => $rep, since => $since };
}

1;
