#!/usr/bin/perl
###############################################################################
# CSF 2.0 - Core Shield Firewall - WHM interface (embedded).
#
# Renders INSIDE the WHM chrome via Cpanel::Template (whostmgr master template),
# exactly like legacy CSF, so it appears with the WHM sidebar rather than as a
# separate page. Falls back to a standalone light-themed page when run outside
# WHM (local preview / testing).
#
# Design: a light, card-based, tabbed UI in the spirit of the cPanel Performance
# Suite, with UnderShield branding. IP lists are rendered client-side with
# search + pagination so thousands of entries stay usable.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################
use strict;
use warnings;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/../../lib", '/usr/local/csf/lib';
use CSF2::Config;
use CSF2::State;
use CSF2::Nft;
use CSF2::Engine;
use CSF2::Health;
use CSF2::Cpanel;
use CSF2::IP;
use CSF2::Profiles;
use CSF2::ThreatIntel;
use CSF2::Cloudflare;

# cPanel's Perl module tree - needed to load Whostmgr::ACLS / Cpanel::Template so
# the plugin can render inside the WHM chrome. The installer also rewrites this
# script's shebang to cPanel's perl (/usr/local/cpanel/3rdparty/bin/perl), which
# is where these modules actually live.
use lib '/usr/local/cpanel';

# Installed version is read from version.txt (written by the installer) so the
# UI never shows a stale number. Falls back to the VERSION file of the package.
my $BUILD_VERSION = do { require CSF2::Version; CSF2::Version::version() };
our $VERSION = do {
    my $vf = ($ENV{CSF2_ETC} || '/etc/csf') . '/version.txt';
    my $v = $BUILD_VERSION;
    if (open my $fh, '<', $vf) { my $l = <$fh>; close $fh; chomp $l if defined $l; $v = $l if defined $l && $l =~ /\S/; }
    $v;
};

# Update channel checked by the WHM UI (the testing channel serves real builds).
our $UPDATE_URL = 'https://shield.underhost.com/firewall/releases/latest.json';

# editable config keys shown on the Configuration tab (defined before use)
our @CFG_TEXT   = qw(TCP_IN UDP_IN TCP_OUT UDP_OUT MGMT_PORTS);
our @CFG_NUM    = qw(T_MONITOR T_THROTTLE T_SHORT_BLOCK T_LONG_BLOCK T_PERM HALFLIFE SAFE_RELOAD_TIMEOUT);
our @CFG_TOGGLE = qw(TESTING IPV6 DROP_LOG);

# --- WHM environment (graceful when absent, e.g. local preview) ---
my ($under_whm, $have_template) = (0, 0);
eval {
    require Whostmgr::ACLS; Whostmgr::ACLS::init_acls();
    die "access denied\n" unless Whostmgr::ACLS::hasroot();
    $under_whm = 1;
};
eval { require Cpanel::Template; $have_template = 1; } if $under_whm;

# Outside WHM this script has no login of its own: it may only run when the
# csf2-ui service launched it for a signed-in user (CSF2_UI_USER), or for an
# explicit local preview (CSF2_PREVIEW=1 from a root shell).
my $ui_user = (!$under_whm && defined $ENV{CSF2_UI_USER} && $ENV{CSF2_UI_USER} =~ /^[A-Za-z0-9_.-]{1,32}$/)
    ? $ENV{CSF2_UI_USER} : '';
unless ($under_whm || $ui_user || $ENV{CSF2_PREVIEW}) {
    print "Status: 403 Forbidden\r\nContent-type: text/plain\r\n\r\naccess denied\n";
    exit 0;
}
my $VIA = $under_whm ? 'via WHM' : ($ui_user ? "via UI ($ui_user)" : 'via preview');

my $etc = $ENV{CSF2_ETC} || '/etc/csf';
my $var = $ENV{CSF2_VAR} || '/var/lib/csf';

my $config = CSF2::Config->loadconfig(file => "$etc/csf.conf");
my %cfg    = $config->config;
my $state  = CSF2::State->new(etc => $etc, var => $var);
my $nft    = CSF2::Nft->new(dry_run => ($ENV{CSF2_DRYRUN} ? 1 : 0), nft => ($cfg{NFT} || '/usr/sbin/nft'));
my $eng    = CSF2::Engine->new(config => $config, state => $state, nft => $nft);
my $cpanel = CSF2::Cpanel->new;

my %P = parse_params();
my $active_tab = $P{tab} || 'dashboard';
my @notice;   # [ok/err, message]
our $OPLOG = '';   # captured output of the last firewall/diagnostic operation

# lightweight polling endpoint for the Update tab's progress bar
if (($P{action} || '') eq 'update-progress') {
    my $c = '0|idle';
    if (open my $f, '<', "$var/update.progress") { local $/; $c = <$f> // '0|idle'; close $f; }
    $c =~ s/\s+$//;
    print "Content-type: text/plain\r\n\r\n$c";
    exit 0;
}

# action dispatch (single call each)
if (my $a = $P{action}) {
    my $ip  = defined $P{ip} ? $P{ip} : '';
    my $cmt = (defined $P{comment} && $P{comment} ne '') ? $P{comment} : $VIA;
    @notice = ();
    my ($ok, $m);
    if    ($a eq 'deny')     { ($ok,$m) = $eng->deny($ip,$cmt) }
    elsif ($a eq 'allow')    { ($ok,$m) = $eng->allow($ip,$cmt) }
    elsif ($a eq 'undeny')   { ($ok,$m) = $eng->undeny($ip) }
    elsif ($a eq 'unallow')  { ($ok,$m) = $eng->unallow($ip) }
    elsif ($a eq 'unblock')  { my ($o1)=$eng->undeny($ip); my ($o2)=$eng->temprm($ip); $ok=($o1||$o2); $m="removed $ip from deny/temp"; }
    elsif ($a eq 'temprm')   { ($ok,$m) = $eng->temprm($ip) }
    elsif ($a eq 'tempdeny') { my $ttl = ($P{ttl} && $P{ttl}=~/^\d+$/)?$P{ttl}:3600; ($ok,$m)=$eng->tempdeny($ip,$ttl,comment=>$cmt) }
    elsif ($a eq 'tempallow'){ my $ttl = ($P{ttl} && $P{ttl}=~/^\d+$/)?$P{ttl}:3600; ($ok,$m)=$eng->tempdeny($ip,$ttl,kind=>'allow',comment=>$cmt) }
    elsif ($a eq 'ignore')   { ($ok,$m) = add_ignore($ip); }
    elsif ($a eq 'reload')   { my $r=$eng->reload(); $ok=$r->{ok}; $m=$r->{ok}?($r->{applied}?'Firewall reloaded (applied)':'Ruleset validated (TESTING - not applied)'):"Reload refused: $r->{error}"; }
    elsif ($a eq 'flush')    { my ($o,$mm)=$state->temp_flush(); $ok=1; $m='Temporary entries flushed'; }
    elsif ($a eq 'fw-start')  { ($ok,$m)=fw_control('start');   $active_tab='firewall'; }
    elsif ($a eq 'fw-stop')   { ($ok,$m)=fw_control('stop');    $active_tab='firewall'; }
    elsif ($a eq 'fw-restart'){ ($ok,$m)=fw_control('restart'); $active_tab='firewall'; }
    elsif ($a eq 'cf-enable') { ($ok,$m)=cf_toggle(1); %cfg = CSF2::Config->loadconfig(file=>"$etc/csf.conf")->config; $active_tab='firewall'; }
    elsif ($a eq 'cf-disable'){ ($ok,$m)=cf_toggle(0); %cfg = CSF2::Config->loadconfig(file=>"$etc/csf.conf")->config; $active_tab='firewall'; }
    elsif ($a eq 'run-selftest'){ ($ok,$m)=run_selftest(); $active_tab='diag'; }
    elsif ($a eq 'saveconfig'){ ($ok,$m) = save_config(); %cfg = CSF2::Config->loadconfig(file=>"$etc/csf.conf")->config; }
    elsif ($a eq 'profile')  { ($ok,$m) = apply_profile($P{name}); %cfg = CSF2::Config->loadconfig(file=>"$etc/csf.conf")->config; }
    elsif ($a eq 'ti-save')  { ($ok,$m) = ti_save(); %cfg = CSF2::Config->loadconfig(file=>"$etc/csf.conf")->config; }
    elsif ($a eq 'ti-update'){ my $r = CSF2::ThreatIntel::update(nft=>$nft, cfg=>{%cfg,TI_ENABLE=>1}, var=>$var); $ok=1; $m="Threat feeds updated: $r->{total} indicators loaded"; }
    elsif ($a eq 'scan-save') { ($ok,$m) = scan_save(); %cfg = CSF2::Config->loadconfig(file=>"$etc/csf.conf")->config; $active_tab='malware'; }
    elsif ($a eq 'scan-now')  { my $bin = csf_bin(); system("nohup $bin --scan >/dev/null 2>&1 &"); $ok=1; $m='Scan started in the background. Reload this tab in a minute to see the results.'; $active_tab='malware'; }
    elsif ($a eq 'scan-update'){ my $bin = csf_bin(); system("nohup $bin --scan-update > '$var/scan-setup.log' 2>&1 &"); $ok=1; $m='Signature update started (about a minute). Progress is shown below.'; $active_tab='malware'; }
    elsif ($a eq 'scan-setup'){ my $bin = csf_bin(); system("nohup $bin --scan-setup > '$var/scan-setup.log' 2>&1 &"); $ok=1; $m='Setup started: installing ClamAV and YARA and downloading signatures (a few minutes). Progress is shown below.'; $active_tab='malware'; }
    elsif ($a eq 'q-restore' or $a eq 'q-delete') {
        require CSF2::Scanner;
        my $sc = CSF2::Scanner->new(cfg => \%cfg, var => $var);
        ($ok,$m) = $a eq 'q-restore' ? $sc->quarantine_restore($P{id}) : $sc->quarantine_delete($P{id});
        $active_tab = 'malware';
    }
    elsif ($a eq 'do-update'){
        # kick off the self-updater in the background; the Update tab polls progress
        if (open my $pf,'>',"$var/update.progress"){ print {$pf} "1|Starting update\n"; close $pf; }
        my $bin = (-x '/usr/local/csf/bin/csf2') ? '/usr/local/csf/bin/csf2' : 'csf2';
        unlink "$var/update.json";   # force a fresh version check after the update
        system("nohup $bin --self-update >/dev/null 2>&1 &");
        $ok = 1; $m = 'Update started - progress is shown below.'; $active_tab = 'update';
    }
    else { $ok = 0; $m = "unknown action: $a"; }
    push @notice, [ $ok ? 'ok' : 'err', $m ] if defined $m;
}

# --- gather (after any mutation) ---
my $deny  = $state->load_list('deny');
my $allow = $state->load_list('allow');
my @temp  = grep { !$_->{expired} } @{ $state->temp_load() };
my ($health, $worst) = CSF2::Health::check(\%cfg, $nft, $state);
my $cpsum   = $cpanel->summary;
my @events  = tail_log("$var/lfd.log", 60);
my $enforcing = $config->is_enforcing;
my $tableok   = $nft->table_exists ? 1 : 0;
my $nd = scalar @$deny; my $na = scalar @$allow; my $nt = scalar @temp;
my $threat = $nt + $nd;
my $threat_level = $threat >= 500 ? 'high' : ($threat >= 50 ? 'elevated' : 'low');
# protection score (0-100): enforcing + table loaded + health + ipv6 + policy drop
my $score = 0;
$score += 40 if $enforcing; $score += 25 if $tableok; $score += 15 if $cfg{IPV6};
$score += 10 if (($cfg{INPUT_POLICY}||'drop') eq 'drop'); $score += 10 if $worst eq 'ok';
$score = 100 if $score > 100;

my ($update_ver, $update_avail) = check_update();

my $html = build_content();

# --- emit: WHM-embedded (inside the WHM chrome) or standalone fallback ---
my $emitted = 0;
if ($have_template && !$ENV{CSF2_STANDALONE}) {
    my $out;
    my $ok = eval {
        $out = Cpanel::Template::process_template('whostmgr', {
            template_file       => 'cpanelshield.tmpl',
            cpanelshield_output => $html,
        });
        1;
    };
    if ($ok && defined $out) {
        my $body = (ref($out) eq 'SCALAR') ? $$out : $out;
        if (defined $body && $body =~ /\S/) {
            print "Content-type: text/html\r\n\r\n";
            print $body;
            $emitted = 1;
        }
    }
}
unless ($emitted) {
    print "Content-type: text/html; charset=utf-8\r\n\r\n" unless $ENV{CSF2_NO_HEADER};
    print "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        . "<title>Core Shield Firewall</title></head><body style='margin:0;background:#eef1f6'>$html</body></html>";
}

###############################################################################
# helpers
sub esc { my $s = shift; $s = '' unless defined $s; $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; return $s }
sub jesc { my $s = shift; $s = '' unless defined $s; $s =~ s/([\\"])/\\$1/g; $s =~ s/\n/ /g; $s =~ s/\r//g; $s =~ s{</}{<\\/}g; return $s }

sub parse_params {
    my %p;
    if ($under_whm) { my $ok = eval { require Cpanel::Form; %p = Cpanel::Form::parseform(); 1 }; return %p if $ok; }
    my $data = '';
    if (($ENV{REQUEST_METHOD}||'') eq 'POST') { local $/; $data = <STDIN> // ''; } else { $data = $ENV{QUERY_STRING} // ''; }
    for my $pair (split /&/, $data) {
        my ($k,$v) = split /=/, $pair, 2; next unless defined $k;
        for ($k,$v) { $_ //= ''; s/\+/ /g; s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge; }
        $p{$k} = $v;
    }
    return %p;
}

# version_newer($a, $b) -> 1 if $a is a newer semver than $b
sub version_newer {
    my ($a, $b) = @_;
    my @a = ($a =~ /(\d+)/g); my @b = ($b =~ /(\d+)/g);
    for my $i (0 .. 3) {
        my $x = $a[$i] // 0; my $y = $b[$i] // 0;
        return 1 if $x > $y; return 0 if $x < $y;
    }
    return 0;
}

# check_update() -> ($latest_version, $update_available)
# Fetches the stable manifest (curl, 3s timeout), cached for 15m in
# $var/update.json. The request URL carries a cache-buster so an intermediate
# CDN (e.g. Cloudflare) can't serve a stale manifest, and a cached copy that is
# behind the installed version is discarded. Fail-safe: any error = no update.
sub check_update {
    my $cache = "$var/update.json";
    my $body  = '';
    my $fresh = (-e $cache && (time - (stat $cache)[9]) < 900);
    if ($fresh) {
        if (open my $c, '<', $cache) { local $/; $body = <$c>; close $c; }
        # if the cached manifest is not newer-or-equal to us, it is stale: refetch
        my ($cv) = ($body // '') =~ /"version"\s*:\s*"([^"]+)"/;
        $fresh = 0 if $cv && version_newer($VERSION, $cv);   # installed > cached
    }
    unless ($fresh) {
        my $curl = (-x '/usr/bin/curl') ? '/usr/bin/curl' : 'curl';
        my $url  = $UPDATE_URL . (($UPDATE_URL =~ /\?/) ? '&' : '?') . '_=' . time;
        $url =~ s/[^A-Za-z0-9:\/._?=&-]//g;   # sanitise (keeps ?=& and digits)
        my $new = `$curl -fsSL --max-time 3 "$url" 2>/dev/null` || '';
        if ($new =~ /"version"/) { $body = $new; if (open my $c, '>', $cache) { print {$c} $body; close $c; } }
    }
    my ($latest) = ($body // '') =~ /"version"\s*:\s*"([^"]+)"/;
    return ('', 0) unless $latest;
    return ($latest, version_newer($latest, $VERSION) ? 1 : 0);
}

sub tail_log {
    my ($file,$n) = @_; return () unless -e $file;
    open my $fh,'<',$file or return (); my @l=<$fh>; close $fh; chomp @l;
    @l = grep { /\S/ } @l;
    return reverse( @l > $n ? @l[-$n..-1] : @l );
}

# env_rows($cpanel_version_html) -> dashboard rows for the environment box:
# the cPanel/cPHulk/ModSecurity trio on cPanel, the detected platform elsewhere.
sub env_rows {
    my ($cpv) = @_;
    my $row = sub { qq{<div class="csfx-hrow"><span class="csfx-dot $_[0]"></span><b>$_[1]</b><span class="csfx-muted">$_[2]</span></div>} };
    if ($cpsum->{cpanel}) {
        return $row->($cpsum->{cpanel} ? 'ok' : 'warn', 'cPanel', $cpv)
             . $row->($cpsum->{cphulk} ? 'ok' : 'warn', 'cPHulk', $cpsum->{cphulk} ? 'enabled (respected)' : 'not enabled')
             . $row->($cpsum->{modsecurity} ? 'ok' : 'warn', 'ModSecurity', $cpsum->{modsecurity} ? 'installed (WAF escalation)' : 'not detected');
    }
    require CSF2::Platform;
    my $pl = CSF2::Platform->new;
    my $p  = $pl->detect;
    return $row->('ok', 'Platform', esc($pl->label($p)))
         . $row->('ok', 'Web UI', $ui_user ? 'standalone (signed in as ' . esc($ui_user) . ')' : 'local preview');
}

sub add_ignore {
    my ($ip) = @_;
    my $p = CSF2::IP::parse($ip) or return (0, "invalid IP: $ip");
    my $f = "$etc/csf.ignore";
    my @cur; if (open my $in,'<',$f){ @cur=<$in>; close $in; }
    return (0,"$p->{canonical} already ignored") if grep { /\b\Q$p->{canonical}\E\b/ } @cur;
    open my $o,'>>',$f or return (0,"open $f: $!"); print {$o} "$p->{canonical} # $VIA\n"; close $o;
    return (1,"$p->{canonical} added to csf.ignore (restart LFD to apply)");
}

# parse_conf_annotated($file) -> arrayref of { key, val, help, kind, section }
# Preserves the comment block above each setting as help text and groups by the
# "### Section ###" banners that appear in csf.conf, so the editor can present
# every option the way legacy CSF does.
# csf_help() -> hashref { KEY => description }
# Bundled descriptions so the config editor shows help text even when the live
# csf.conf has no comments (e.g. a migrated config). Values in the live file's
# own comments take precedence.
my %HELP;
sub csf_help {
    return \%HELP if %HELP;
    for my $p ("/usr/local/csf/csf.conf.help", "$Bin/../etc/csf.conf.help", "$etc/csf.conf.help") {
        next unless -e $p;
        open my $fh, '<', $p or next;
        while (my $l = <$fh>) { chomp $l; my ($k,$d) = split /\|/, $l, 2; $HELP{$k} = $d if defined $d; }
        close $fh; last;
    }
    return \%HELP;
}

sub parse_conf_annotated {
    my ($file) = @_;
    my (@entries, @cbuf);
    my $section = 'General';
    open my $fh, '<', $file or return [];
    while (my $l = <$fh>) {
        chomp $l;
        if ($l =~ /^\s*#+\s*(.*?)\s*#*\s*$/) {
            my $c = $1;
            # a line that is only #### ... #### with a Title is a section banner
            if ($l =~ /^#{3,}/ && $c =~ /\S/ && $c !~ /[a-z]/ ) { $section = $c; @cbuf=(); }
            elsif ($l =~ /^\s*#{3,}\s*$/) { }   # decorative rule
            else { push @cbuf, $c if $c ne '' || @cbuf; }
            next;
        }
        if ($l =~ /^\s*$/) { next; }
        if ($l =~ /^\s*([A-Z0-9_]+)\s*=\s*"?(.*?)"?\s*$/) {
            my ($k, $v) = ($1, $2);
            my $help = join(' ', grep { defined && length } @cbuf);
            $help =~ s/\s+/ /g; $help =~ s/^\s+|\s+$//g;
            @cbuf = ();
            my $kind = ($v eq '0' || $v eq '1') ? 'toggle' : ($v =~ /^\d+$/ ? 'num' : 'text');
            push @entries, { key=>$k, val=>$v, help=>$help, kind=>$kind, section=>$section };
        } else { @cbuf = (); }
    }
    close $fh;
    return \@entries;
}

sub csf_bin { return (-x '/usr/local/csf/bin/csf2') ? '/usr/local/csf/bin/csf2' : 'csf2'; }

# render a comma-separated port list as chips
sub port_chips {
    my ($str) = @_;
    $str = '' unless defined $str;
    $str =~ s/^\s+|\s+$//g;
    return '<span class="csfx-portnone">none</span>' if $str eq '';
    my @p = grep { length } split /\s*,\s*/, $str;
    return join('', map { '<span class="csfx-chip">'.esc($_).'</span>' } @p);
}

# run a shell command, capture combined stdout+stderr into $OPLOG (trimmed)
sub op_run {
    my ($label, $cmd) = @_;
    my $out = `$cmd 2>&1`;
    $out = '' unless defined $out;
    $out =~ s/\s+$//;
    $OPLOG .= "\$ $label\n" . ($out ne '' ? $out : '(no output)') . "\n\n";
    return $out;
}

# fw_control(start|stop|restart) -> (ok, message). Captures logs into $OPLOG.
sub fw_control {
    my ($op) = @_;
    my $bin = csf_bin();
    if ($op eq 'start') {
        op_run('systemctl enable --now csf.service lfd.service', 'systemctl enable --now csf.service lfd.service');
        op_run("$bin --initup", "$bin --initup");
        return (1, 'Firewall started - services enabled and ruleset applied.');
    }
    elsif ($op eq 'stop') {
        op_run('systemctl stop csf.service lfd.service', 'systemctl stop csf.service lfd.service');
        op_run("$bin --initdown", "$bin --initdown");
        return (1, 'Firewall stopped - nftables table removed. The server is UNPROTECTED until you start it again.');
    }
    elsif ($op eq 'restart') {
        op_run('systemctl restart csf.service lfd.service', 'systemctl restart csf.service lfd.service');
        op_run("$bin --initup", "$bin --initup");
        return (1, 'Firewall restarted - services bounced and ruleset re-applied.');
    }
    return (0, "unknown firewall operation");
}

# cf_toggle(1|0) -> (ok, message). Adds/removes Cloudflare edge ranges.
sub cf_toggle {
    my ($on) = @_;
    if ($on) {
        my ($ok, $msg, $n) = CSF2::Cloudflare::enable(eng => $eng);
        return (0, "Cloudflare: $msg") unless $ok;
        CSF2::Config->save_keys("$etc/csf.conf", { CF_ENABLE => '1' });
        $OPLOG .= "\$ csf --cf-enable\nCloudflare edge ranges added to the allow list ($n ranges).\n\n";
        return (1, "Cloudflare integration enabled - $msg.");
    } else {
        my ($ok, $msg, $n) = CSF2::Cloudflare::disable(eng => $eng, state => $state);
        CSF2::Config->save_keys("$etc/csf.conf", { CF_ENABLE => '0' });
        $OPLOG .= "\$ csf --cf-disable\n$msg.\n\n";
        return (1, "Cloudflare integration disabled - $msg.");
    }
}

# run_selftest() -> (ok, message). Runs csf --selftest and captures the report.
sub run_selftest {
    my $bin = csf_bin();
    my $out = op_run("$bin --selftest", "$bin --selftest");
    my $bad = ($out =~ /FAIL/) ? 1 : 0;
    return (!$bad, $bad ? 'Self-test finished with failures - see the report below.' : 'Self-test passed - see the report below.');
}

# scan_save() -> (ok, message). Malware Scan tab settings.
sub scan_save {
    my $to = defined $P{SCAN_ALERT_TO} ? $P{SCAN_ALERT_TO} : '';
    $to =~ s/^\s+|\s+$//g;
    my $addr = qr/[A-Za-z0-9._%+\-]+\@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/;
    return (0, 'Alert email: enter one or more addresses separated by commas, "none", or leave it empty')
        if $to ne '' && lc($to) ne 'none' && $to !~ /^$addr(?:\s*,\s*$addr)*$/;
    my %kv = (
        SCAN_ENABLE         => ($P{SCAN_ENABLE} ? '1' : '0'),
        SCAN_ACTION         => (($P{SCAN_ACTION} // '') eq 'alert' ? 'alert' : 'quarantine'),
        SCAN_BLOCK_UPLOADER => ($P{SCAN_BLOCK_UPLOADER} ? '1' : '0'),
        SCAN_ALERT_TO       => $to,
    );
    my ($ok, $m) = CSF2::Config->save_keys("$etc/csf.conf", \%kv);
    return ($ok, $ok ? 'Malware scan settings saved.' : "Save failed: $m");
}

sub ti_save {
    my %kv = (TI_ENABLE => ($P{TI_ENABLE} ? '1' : '0'));
    for my $f (CSF2::ThreatIntel::feeds()) {
        my $key = 'TI_' . uc($f->{id});
        $kv{$key} = ($P{$key} ? '1' : '0');
    }
    my ($ok, $m) = CSF2::Config->save_keys("$etc/csf.conf", \%kv);
    return ($ok, $ok ? 'Threat Intelligence settings saved. Reload the firewall to apply, then Update feeds.' : "Save failed: $m");
}

sub apply_profile {
    my ($name) = @_;
    $name = '' unless defined $name;
    my $pc = CSF2::Profiles::config_for($name);
    return (0, "unknown security level") unless $pc;
    my ($ok, $msg) = CSF2::Config->save_keys("$etc/csf.conf", $pc);
    return (0, "apply failed: $msg") unless $ok;
    # remember the chosen level (informational)
    if (open my $mf, '>', "$var/profile") { print {$mf} $name; close $mf; }
    my $label = CSF2::Profiles::get($name)->{label};
    return (1, "Security level set to $label. Reload the firewall and restart LFD to apply (lfd picks up new thresholds on restart).");
}

sub save_config {
    my $entries = parse_conf_annotated("$etc/csf.conf");
    my %kv;
    for my $e (@$entries) {
        my $k = $e->{key};
        next unless defined $P{$k};
        $kv{$k} = $P{$k};
    }
    return (0, 'no settings submitted') unless %kv;
    my ($ok, $m) = CSF2::Config->save_keys("$etc/csf.conf", \%kv);
    return ($ok, $ok ? scalar(keys %kv)." settings saved. Reload the firewall to apply port/policy changes." : "Save failed: $m");
}

###############################################################################
# content fragment
sub build_content {
    # brand mark: the installed CSF logo, served from the plugin directory.
    # full CSF wordmark logo (served from the plugin dir); light theme.
    my $logo_url = $under_whm ? '/cgi/cpanelshield/logo.png' : '/assets/logo.png';
    my $shield = '<img src="' . $logo_url . '" alt="CSF - Core Shield Firewall" '
               . 'style="height:46px;width:auto;display:block">';
    my $statuspill = $tableok
        ? ($enforcing ? '<span class="csfx-pill ok">Enabled &amp; Enforcing</span>'
                      : '<span class="csfx-pill warn">Loaded &middot; TESTING</span>')
        : '<span class="csfx-pill bad">Not loaded</span>';

    # notices
    my $notices = '';
    for my $n (@notice) {
        my $cls = $n->[0] eq 'ok' ? 'ok' : 'bad';
        $notices .= "<div class='csfx-note $cls'>".esc($n->[1])."</div>";
    }
    # update-available banner -> one click jumps to the Update tab
    if ($update_avail) {
        my $uv = esc($update_ver);
        $notices .= "<div class='csfx-note upd'><span><b>Update available: v$uv</b> "
                  . "&middot; you have v" . esc($VERSION) . "</span>"
                  . "<button type='button' class='csfx-goupd' data-goupdate='1'>Update now &rarr;</button></div>";
    }

    # deny/allow/temp data as JSON for client-side table
    my $deny_json  = join(',', map { '{"ip":"'.jesc($_->{canonical}).'","note":"'.jesc($_->{comment}).'"}' } @$deny);
    my $allow_json = join(',', map { '{"ip":"'.jesc($_->{canonical}).'","note":"'.jesc($_->{comment}).'"}' } @$allow);
    my $temp_json  = join(',', map {
        my $rem = $_->{expires}-time; '{"ip":"'.jesc($_->{ip}).'","note":"'.jesc(($_->{kind}||'deny')." &middot; ".($rem>0?"${rem}s left":"expired")." &middot; ".$_->{comment}).'"}'
    } @temp);

    my $events_html = @events
        ? join('', map { '<div class="csfx-ev">'.esc($_).'</div>' } @events)
        : '<div class="csfx-muted">No recent LFD events.</div>';

    # health rows
    my $health_html = join('', map {
        my %m=(ok=>'ok',warn=>'warn',fail=>'bad');
        '<div class="csfx-hrow"><span class="csfx-dot '.($m{$_->{status}}||'ok').'"></span><b>'.esc($_->{name}).'</b><span class="csfx-muted">'.esc($_->{detail}).'</span></div>'
    } @$health);

    # extensive config editor: every setting, grouped by section, with help text
    my $config_html = '';
    my $cfg_count = 0;
    my $cur_section = '';
    my $help = csf_help();
    for my $e (@{ parse_conf_annotated("$etc/csf.conf") }) {
        $e->{help} = $help->{$e->{key}} if $e->{help} eq '' && $help->{$e->{key}};
        $cfg_count++;
        if ($e->{section} ne $cur_section) {
            $config_html .= '</div>' if $cur_section ne '';
            $cur_section = $e->{section};
            $config_html .= '<div class="csfx-sec" data-sec="'.esc($cur_section).'"><div class="csfx-sec-h">'.esc($cur_section).'</div>';
        }
        my $k = esc($e->{key});
        my $help = $e->{help} ne '' ? '<div class="csfx-help">'.esc($e->{help}).'</div>' : '';
        my $ctrl;
        if ($e->{kind} eq 'toggle') {
            my $on = ($e->{val} eq '1');
            $ctrl = '<span class="csfx-seg">'
                  . '<label class="'.(!$on?'sel':'').'"><input type="radio" name="'.$k.'" value="0"'.(!$on?' checked':'').'>Off</label>'
                  . '<label class="'.($on?'sel':'').'"><input type="radio" name="'.$k.'" value="1"'.($on?' checked':'').'>On</label></span>';
        } else {
            my $wide = length($e->{val}) > 32 ? ' wide' : '';
            $ctrl = '<input type="text" class="csfx-cfg-in'.$wide.'" name="'.$k.'" value="'.esc($e->{val}).'">';
        }
        $config_html .= '<div class="csfx-cfg" data-k="'.esc(lc($e->{key})).' '.esc(lc($e->{help})).'">'
                      . '<div class="csfx-cfg-top"><label class="csfx-cfg-k">'.$k.'</label>'.$ctrl.'</div>'.$help.'</div>';
    }
    $config_html .= '</div>' if $cur_section ne '';

    # security-level profiles
    my $active_profile = CSF2::Profiles::detect(\%cfg);
    my $profiles_html = '';
    for my $pn (CSF2::Profiles::names) {
        my $p = CSF2::Profiles::get($pn);
        my $is = ($pn eq $active_profile);
        my $c = $p->{config};
        my $summary = "block \@ $c->{T_SHORT_BLOCK} &middot; perm after $c->{PERM_AFTER} &middot; memory "
                    . sprintf('%dm', int($c->{HALFLIFE}/60)) . ($c->{DROP_LOG} ? ' &middot; logging' : '');
        $profiles_html .=
            '<div class="csfx-prof '.($is?'active':'').' lvl-'.$pn.'">'
          . '<div class="csfx-prof-h"><span class="csfx-prof-name">'.esc($p->{label}).'</span>'
          . ($is?'<span class="csfx-prof-badge">Active</span>':'').'</div>'
          . '<div class="csfx-prof-tag">'.esc($p->{tagline}).'</div>'
          . '<div class="csfx-prof-desc">'.esc($p->{desc}).'</div>'
          . '<div class="csfx-prof-sum">'.$summary.'</div>'
          . '<form method="post"><input type="hidden" name="tab" value="security"><input type="hidden" name="name" value="'.esc($pn).'">'
          . '<button class="csfx-btn '.($pn eq 'attack'?'r':($pn eq 'high'?'b':'o')).'" name="action" value="profile"'.($is?' disabled':'').'>'
          . ($is?'Currently active':'Apply '.esc($p->{label})).'</button></form>'
          . '</div>';
    }
    my $active_label = $active_profile ? esc(CSF2::Profiles::get($active_profile)->{label}) : 'Custom';

    # --- threat intelligence ---
    my $ti_status = CSF2::ThreatIntel::status($var);
    my %ti_count  = map { $_->{id} => $_->{count} } @{ $ti_status->{feeds} };
    my $ti_on     = $cfg{TI_ENABLE} ? 1 : 0;
    my $ti_feeds_html = '';
    my %cat_color = (high => 'm', botnet => 'a', attackers => 'b');
    for my $f (CSF2::ThreatIntel::feeds()) {
        my $key = 'TI_' . uc($f->{id});
        my $on  = CSF2::ThreatIntel::feed_enabled(\%cfg, $f);
        my $cnt = $ti_count{$f->{id}} // 0;
        my $cc  = $cat_color{$f->{category}} || 'b';
        $ti_feeds_html .=
            '<div class="csfx-feed">'
          . '<div class="csfx-feed-h"><span class="csfx-feed-name">'.esc($f->{name}).'</span>'
          . '<span class="csfx-catpill '.$cc.'">'.esc($f->{category}).'</span></div>'
          . '<div class="csfx-feed-meta">'.esc($f->{vendor}).' &middot; updates '.esc($f->{interval})
          . ($on ? " &middot; <b>$cnt</b> indicators" : '').'</div>'
          . '<label class="csfx-toggle"><input type="checkbox" name="'.$key.'" value="1"'.($on?' checked':'').'>'
          . '<span class="csfx-track"></span><span class="csfx-tlabel">'
          . ($on ? '<span class="on">ON</span>' : '<span class="off">OFF</span>').'</span></label>'
          . '</div>';
    }
    my $ti_updated = $ti_status->{updated} ? scalar(localtime($ti_status->{updated})) : 'never';
    my $ti_total   = $ti_status->{total};

    # --- malware scanning (CSF2::Scanner) ---
    require CSF2::Scanner;
    my $scn   = CSF2::Scanner->new(cfg => \%cfg, var => $var);
    my $sst   = $scn->status;
    my @qlist = sort { ($b->{time} || 0) <=> ($a->{time} || 0) } $scn->quarantine_list;
    my $nq    = scalar @qlist;
    my $sc_on    = $sst->{enabled};
    my $sc_ready = ($sst->{engines}{clamav} || $sst->{engines}{yara}) ? 1 : 0;
    my $sc_ago   = sub { my $t = shift; return 'never' unless $t; my $mn = int((time - $t) / 60); return $mn < 1 ? 'just now' : $mn < 120 ? "$mn min ago" : $mn < 2880 ? int($mn / 60) . ' h ago' : int($mn / 1440) . ' days ago' };
    my $sc_eng   = join(' &middot; ',
        'ClamAV ' . ($sst->{engines}{clamav} ? '<b>ready</b>' : ($sst->{clamscan} ? 'no signatures' : 'not installed')),
        'YARA '   . ($sst->{engines}{yara}   ? '<b>ready</b>' : ($sst->{yara} ? 'no rules' : 'not installed')),
        'heuristics <b>on</b>');
    my $sc_sigs  = $sst->{sigs_at} ? 'updated ' . $sc_ago->($sst->{sigs_at}) . ($sst->{rfxn_ver} ? ' &middot; rfxn ' . esc($sst->{rfxn_ver}) : '') : 'not downloaded yet';
    my $sc_last  = $sc_ago->((stat "$var/scan.last")[9]);
    my $sc_pill  = !$sc_on ? '<span class="csfx-pill warn">Off</span>'
                 : ($sst->{imunify} && !$cfg{SCAN_FORCE}) ? '<span class="csfx-pill ok">Imunify360 active</span>'
                 : $sc_ready ? '<span class="csfx-pill ok">On</span>' : '<span class="csfx-pill warn">On - no engine ready</span>';
    my $sc_roots = @{ $sst->{roots} } ? join('<br>', map { '<code>' . esc($_) . '</code>' } @{ $sst->{roots} }) : 'none found';
    my $q_rows = '';
    for my $q (@qlist) {
        my @t = localtime($q->{time} || 0);
        my $id = esc($q->{id});
        $q_rows .= '<tr><td style="white-space:nowrap">' . sprintf('%04d-%02d-%02d %02d:%02d', $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1]) . '</td>'
                 . '<td style="word-break:break-all"><code>' . esc($q->{path}) . '</code></td>'
                 . '<td>' . esc($q->{signature}) . '<br><span class="csfx-muted">' . esc($q->{engine}) . '</span></td>'
                 . '<td>' . ($q->{ip} ? esc($q->{ip}) : '&mdash;') . '</td>'
                 . '<td style="white-space:nowrap"><form method="post" style="display:inline"><input type="hidden" name="tab" value="malware"><input type="hidden" name="id" value="' . $id . '">'
                 . '<button class="csfx-btn o" name="action" value="q-restore" data-confirm="Put this file back where it was? Only do this if you are sure it is not malware.">Restore</button> '
                 . '<button class="csfx-btn r" name="action" value="q-delete" data-confirm="Delete this file permanently?">Delete</button></form></td></tr>';
    }
    my $q_html = $nq
        ? '<table class="csfx-tbl"><tr><th>Found</th><th>File</th><th>Signature</th><th>Uploader</th><th></th></tr>' . $q_rows . '</table>'
        : '<p class="csfx-muted" style="margin:0">Nothing in quarantine.</p>';
    my @sc_log;
    if (open my $lf, '<', '/var/log/csf2-scan.log') { @sc_log = <$lf>; close $lf; }
    my $sc_log_html = @sc_log ? '<pre style="max-height:280px;overflow:auto;font-size:12px;margin:0">' . esc(join('', reverse @sc_log[($#sc_log > 39 ? $#sc_log - 39 : 0) .. $#sc_log])) . '</pre>'
                              : '<p class="csfx-muted" style="margin:0">No scan activity logged yet.</p>';
    my $sc_setup_html = '';
    if (-s "$var/scan-setup.log" && (stat "$var/scan-setup.log")[9] > time - 3600) {
        my $txt = ''; if (open my $sf, '<', "$var/scan-setup.log") { local $/; $txt = <$sf> // ''; close $sf; }
        $sc_setup_html = '<div class="csfx-oplog"><div class="csfx-oplog-h">Setup / update output</div><pre>' . esc($txt =~ s/\s+$//r) . '</pre></div>';
    }
    my $sc_alert_to = esc($cfg{SCAN_ALERT_TO} // '');
    my $sc_alert_default = esc($cfg{LF_ALERT_TO} || 'root');
    my $sc_tab = 'Malware Scan' . ($nq ? " ($nq)" : '');

    my $ver = esc($VERSION);
    my $cpv = esc($cpsum->{version} // 'n/a');
    my $tcp_in  = esc($cfg{TCP_IN}//'');
    my $tcp_out = esc($cfg{TCP_OUT}//'');
    my $udp_in  = esc($cfg{UDP_IN}//'');
    my $udp_out = esc($cfg{UDP_OUT}//'');
    my $under = under_wordmark();

    # Cloudflare integration state
    my $cf_count = CSF2::Cloudflare::count_active($state);
    my $cf_on    = ($cfg{CF_ENABLE} || $cf_count) ? 1 : 0;

    # Cloudflare-style cloud mark (inline SVG, brand orange) - labels the integration.
    # Built from overlapping circles + a rounded base so it reads as a clean cloud.
    my $CF_LOGO = '<svg viewBox="0 0 72 44" width="60" height="37" xmlns="http://www.w3.org/2000/svg" aria-label="Cloudflare">'
      . '<g fill="#F6821F">'
      . '<circle cx="24" cy="26" r="12"/>'
      . '<circle cx="40" cy="18" r="16"/>'
      . '<circle cx="53" cy="28" r="10"/>'
      . '<rect x="18" y="26" width="39" height="14" rx="7"/>'
      . '</g>'
      . '<rect x="25" y="30" width="30" height="4.6" rx="2.3" fill="#FBAD41"/>'
      . '</svg>';

    # 1 only on the request that actually kicked off an update, so the progress
    # bar polls/reloads then - never on a plain visit to the Update tab (a stale
    # "100" in the progress file must not cause a reload loop).
    my $just_update = ((defined $P{action} && $P{action} eq 'do-update') ? 1 : 0);

    # captured operation log (firewall control / cloudflare / self-test)
    my $oplog_html = ($OPLOG ne '')
        ? '<div class="csfx-oplog"><div class="csfx-oplog-h">Operation log</div><pre>'.esc($OPLOG =~ s/\s+$//r).'</pre></div>'
        : '';
    my $updot = $update_avail ? ' <span class="csfx-updot" title="Update available"></span>' : '';
    my $uplatest = $update_ver ? 'v'.esc($update_ver) : '&mdash;';
    my ($upstate, $upbtnlabel, $updisabled);
    if ($update_avail) {
        $upstate = '<span class="csfx-pill warn">Update available</span>';
        $upbtnlabel = 'Update to v'.esc($update_ver).' now';
        $updisabled = '';
    } else {
        $upstate = '<span class="csfx-pill ok">Up to date</span>';
        $upbtnlabel = 'Check &amp; re-install';
        $updisabled = '';
    }

    return <<"HTML";
<div class="csfx-app" id="csfx">
<style>
.csfx-app{--blue:#2563eb;--blue-d:#1d4ed8;--green:#16a34a;--red:#dc2626;--amber:#d97706;--cyan:#00b0f4;
 --ink:#111827;--muted:#6b7280;--line:#e5e7eb;--bg:#f3f4f6;--card:#fff;
 font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:var(--ink);
 background:var(--bg);padding:18px;border-radius:10px;line-height:1.5;-webkit-font-smoothing:antialiased}
.csfx-app *{box-sizing:border-box}
.csfx-head{display:flex;align-items:center;gap:14px;margin-bottom:18px;flex-wrap:wrap}
.csfx-head .mk{flex:0 0 auto;display:flex}
.csfx-verlbl{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--muted);background:#f1f5f9;border:1px solid var(--line);border-radius:50px;padding:2px 9px}
.csfx-title{font-size:20px;font-weight:700;letter-spacing:-.01em}
.csfx-title small{display:block;font-size:11px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-top:2px}
.csfx-head .right{margin-left:auto;display:flex;align-items:center;gap:14px}
.csfx-under{display:inline-flex;align-items:center;flex-shrink:0;line-height:0}
.csfx-under img{max-width:none}
.csfx-pill{font-size:12px;font-weight:600;padding:5px 11px;border-radius:999px}
.csfx-pill.ok{color:#166534;background:#dcfce7;border:1px solid #bbf7d0}
.csfx-pill.warn{color:#92400e;background:#fef3c7;border:1px solid #fde68a}
.csfx-pill.bad{color:#991b1b;background:#fee2e2;border:1px solid #fecaca}
.csfx-tabs{display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid var(--line);margin-bottom:18px}
.csfx-tab{border:0;background:none;padding:10px 15px;font-size:13.5px;font-weight:600;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}
.csfx-tab:hover{color:var(--ink)}
.csfx-tab.active{color:var(--blue);border-bottom-color:var(--blue)}
.csfx-panel{display:none}.csfx-panel.active{display:block}
.csfx-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:18px}
.csfx-card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.csfx-card .k{font-size:26px;font-weight:700}.csfx-card .l{font-size:12.5px;color:var(--muted);margin-top:2px}
.csfx-k-green{color:var(--green)}.csfx-k-red{color:var(--red)}.csfx-k-amber{color:var(--amber)}.csfx-k-blue{color:var(--blue)}
.csfx-grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
\@media(max-width:820px){.csfx-grid2{grid-template-columns:1fr}}
.csfx-box{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:16px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.csfx-box h3{margin:0 0 14px;font-size:15px;font-weight:700}
.csfx-gauge{display:flex;align-items:center;gap:16px}
.csfx-gauge .num{font-size:34px;font-weight:800}
.csfx-actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.csfx-app input[type=text],.csfx-app select{border:1px solid var(--line);border-radius:8px;padding:8px 11px;font-size:13.5px;background:#fff;color:var(--ink)}
.csfx-app input[type=text]:focus,.csfx-app select:focus{outline:2px solid var(--blue);border-color:var(--blue)}
.csfx-btn{cursor:pointer;font-weight:600;border:1px solid transparent;border-radius:8px;padding:8px 15px;font-size:13.5px}
.csfx-btn.b{background:var(--blue);color:#fff}.csfx-btn.b:hover{background:var(--blue-d)}
.csfx-btn.g{background:var(--green);color:#fff}.csfx-btn.r{background:var(--red);color:#fff}
.csfx-btn.o{background:#fff;border-color:var(--line);color:var(--ink)}.csfx-btn.o:hover{background:#f9fafb}
.csfx-btn.mini{padding:4px 10px;font-size:12px;background:#fff;border-color:var(--line);color:var(--red)}
.csfx-note{padding:11px 14px;border-radius:9px;margin-bottom:14px;font-size:13.5px}
.csfx-note.ok{background:#dcfce7;border:1px solid #bbf7d0;color:#166534}
.csfx-note.bad{background:#fee2e2;border:1px solid #fecaca;color:#991b1b}
.csfx-note.upd{background:#eff3ff;border:1px solid #c7d5ff;color:#1e3a8a;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.csfx-goupd{margin-left:auto;cursor:pointer;font-weight:700;border:0;border-radius:8px;padding:7px 14px;font-size:13px;background:var(--blue);color:#fff}
.csfx-goupd:hover{background:var(--blue-d)}
.csfx-updot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--red);box-shadow:0 0 0 3px rgba(220,38,38,.18);vertical-align:middle}
.csfx-uprow{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:6px}
\@media(max-width:640px){.csfx-uprow{grid-template-columns:1fr}}
.csfx-upcol{background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:14px}
.csfx-upk{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.csfx-upv{font-size:19px;font-weight:700;margin-top:6px}
.csfx-upbar-wrap{margin-top:18px}
.csfx-upbar{height:14px;background:#e5e7eb;border-radius:999px;overflow:hidden}
.csfx-upbar-fill{height:100%;width:0;background:linear-gradient(90deg,#2563eb,#00b0f4);border-radius:999px;transition:width .4s ease}
.csfx-upbar-fill.err{background:var(--red)}
.csfx-upmsg{font-size:13px;color:var(--muted);margin-top:8px;font-weight:600}
.csfx-uhlink{color:var(--cyan);font-weight:700;text-decoration:none}.csfx-uhlink:hover{text-decoration:underline}
/* firewall control */
.csfx-fwhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.csfx-ctlbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:16px}
.csfx-ctlbar form{margin:0}
.csfx-ctlsep{width:1px;height:26px;background:var(--line);margin:0 4px}
.csfx-ctl{cursor:pointer;display:inline-flex;align-items:center;gap:7px;font-weight:700;font-size:13.5px;border:1px solid transparent;border-radius:8px;padding:9px 16px;color:#fff}
.csfx-ctl .csfx-ci{font-size:12px;line-height:1}
.csfx-ctl.start{background:var(--green)}.csfx-ctl.start:hover{background:#15803d}
.csfx-ctl.restart{background:var(--blue)}.csfx-ctl.restart:hover{background:var(--blue-d)}
.csfx-ctl.stop{background:var(--red)}.csfx-ctl.stop:hover{background:#b91c1c}
.csfx-oplog{background:#f8fafc;border:1px solid var(--line);border-radius:10px;margin:0 0 16px;overflow:hidden}
.csfx-oplog-h{font:700 11px/1 ui-monospace,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase;color:#475569;padding:9px 12px;border-bottom:1px solid var(--line);background:#eef2f7}
.csfx-app .csfx-oplog pre{margin:0;padding:12px;max-height:280px;overflow:auto;background:transparent;color:#0f172a;font:12.5px/1.6 ui-monospace,'JetBrains Mono',Menlo,monospace;white-space:pre-wrap;word-break:break-word}
.csfx-statgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.csfx-stat{background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:13px 14px}
.csfx-stat-k{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.csfx-stat-v{margin-top:8px}
.csfx-badge{display:inline-block;font-size:12px;font-weight:700;padding:4px 10px;border-radius:50px}
.csfx-badge.g{color:#166534;background:#dcfce7;border:1px solid #bbf7d0}
.csfx-badge.a{color:#92400e;background:#fef3c7;border:1px solid #fde68a}
.csfx-badge.r{color:#991b1b;background:#fee2e2;border:1px solid #fecaca}
.csfx-ports{background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.csfx-porthead{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:10px}
.csfx-portrow{display:flex;align-items:flex-start;gap:12px;padding:7px 0;border-top:1px solid #eef1f6}
.csfx-portrow:first-of-type{border-top:0}
.csfx-portlbl{flex:0 0 66px;font-size:12.5px;font-weight:700;color:#475569;padding-top:3px}
.csfx-portval{display:flex;flex-wrap:wrap;gap:5px}
.csfx-chip{font:12px ui-monospace,Menlo,monospace;background:#eef2ff;border:1px solid #dbe1ff;color:#3730a3;border-radius:6px;padding:2px 7px}
.csfx-portnone{color:var(--muted);font-size:12.5px}
.csfx-porthint{margin-top:10px;font-size:12px;color:var(--muted)}
/* cloudflare */
.csfx-cf{border-color:var(--line)}
.csfx-cf.on{border-color:#f6821f;box-shadow:0 0 0 1px rgba(246,130,31,.25)}
.csfx-cfrow{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.csfx-cflogo{flex:0 0 auto;display:flex;align-items:center}
.csfx-cfbody{flex:1 1 300px;min-width:0}
.csfx-cftitle{font-size:15px;font-weight:700;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.csfx-cfact{flex:0 0 auto}.csfx-cfact form{margin:0}
.csfx-btn.cf{background:#f6821f;color:#fff}.csfx-btn.cf:hover{background:#e2740f}
.csfx-tests .csfx-actions{margin-bottom:2px}
.csfx-tools{display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
.csfx-tools input{flex:1;min-width:200px}
.csfx-count{font-size:12.5px;color:var(--muted)}
table.csfx-tbl{width:100%;border-collapse:collapse;font-size:13px}
.csfx-tbl th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:8px 10px;border-bottom:1px solid var(--line)}
.csfx-tbl td{padding:9px 10px;border-bottom:1px solid #f1f5f9;vertical-align:top}
.csfx-tbl td.ip{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:600;white-space:nowrap}
.csfx-pg{display:flex;gap:6px;align-items:center;justify-content:center;margin-top:12px}
.csfx-pg button{border:1px solid var(--line);background:#fff;border-radius:7px;padding:5px 11px;cursor:pointer;font-size:13px}
.csfx-pg button:disabled{opacity:.4;cursor:default}
.csfx-hrow{display:flex;align-items:center;gap:9px;padding:6px 0;font-size:13.5px}
.csfx-hrow b{min-width:150px}
.csfx-dot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}
.csfx-dot.ok{background:var(--green)}.csfx-dot.warn{background:var(--amber)}.csfx-dot.bad{background:var(--red)}
.csfx-muted{color:var(--muted)}
.csfx-ev{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#374151;padding:5px 0;border-bottom:1px solid #f1f5f9}
.csfx-field{display:flex;flex-direction:column;gap:5px;margin-bottom:12px}
.csfx-field span{font-size:12px;font-weight:600;color:var(--muted)}
.csfx-field.sm{display:inline-flex;width:170px;margin-right:12px}
.csfx-check{display:inline-flex;align-items:center;gap:7px;margin-right:18px;font-size:13.5px;font-weight:600}
.csfx-foot{margin-top:24px;padding-top:16px;border-top:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:18px;flex-wrap:wrap}
.csfx-foot-l{display:flex;flex-direction:column;gap:2px;line-height:1.45}
.csfx-foot-l .t{font-size:13px;color:var(--ink)}.csfx-foot-l .t b{font-weight:700}
.csfx-foot-l .t .v{margin-left:6px;color:var(--muted);font:600 11px ui-monospace,Menlo,monospace}
.csfx-foot-l .sub{font-size:11.5px;color:var(--muted)}
.csfx-foot-r{display:flex;align-items:center;gap:12px}
.csfx-foot-r .pb{font-size:12px;color:var(--muted)}
/* config editor */
.csfx-sec{margin-bottom:10px}
.csfx-sec-h{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--blue);background:#eff3ff;border:1px solid #dbe4ff;border-radius:8px;padding:8px 12px;margin:16px 0 8px}
.csfx-cfg{padding:11px 12px;border:1px solid var(--line);border-radius:9px;margin-bottom:8px;background:#fff}
.csfx-cfg-top{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.csfx-cfg-k{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;font-size:13px;min-width:210px}
.csfx-cfg-in{flex:1;min-width:220px}.csfx-cfg-in.wide{min-width:100%;flex-basis:100%}
.csfx-help{font-size:12.5px;color:var(--muted);margin-top:7px;line-height:1.5}
.csfx-seg{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.csfx-seg label{padding:6px 16px;font-size:13px;font-weight:600;cursor:pointer;color:var(--muted);background:#fff}
.csfx-seg label.sel{background:var(--blue);color:#fff}
.csfx-seg input{position:absolute;opacity:0;pointer-events:none}
.csfx-savebar{position:sticky;bottom:0;background:#fff;border-top:1px solid var(--line);margin-top:14px;padding:12px 0;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
/* security-level profiles */
.csfx-profs{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}
.csfx-prof{border:1px solid var(--line);border-radius:12px;padding:18px;background:#fff;display:flex;flex-direction:column;border-top:4px solid #cbd5e1}
.csfx-prof.lvl-low{border-top-color:#16a34a}.csfx-prof.lvl-medium{border-top-color:#2563eb}
.csfx-prof.lvl-high{border-top-color:#d97706}.csfx-prof.lvl-attack{border-top-color:#dc2626}
.csfx-prof.active{box-shadow:0 0 0 2px var(--blue);border-color:var(--blue)}
.csfx-prof-h{display:flex;align-items:center;justify-content:space-between}
.csfx-prof-name{font-family:'Space Grotesk',var(--body);font-weight:700;font-size:17px}
.csfx-prof-badge{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#166534;background:#dcfce7;border:1px solid #bbf7d0;border-radius:50px;padding:2px 8px}
.csfx-prof-tag{font-size:12.5px;font-weight:600;color:var(--muted);margin:2px 0 10px}
.csfx-prof-desc{font-size:12.8px;color:#374151;line-height:1.55;flex:1}
.csfx-prof-sum{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--muted);margin:12px 0;padding:8px 10px;background:#f8fafc;border:1px solid var(--line);border-radius:8px}
.csfx-prof .csfx-btn{width:100%;justify-content:center}
.csfx-prof .csfx-btn:disabled{opacity:.55;cursor:default}
/* threat intelligence */
.csfx-ti-master{padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:#f8fafc;margin-bottom:14px}
.csfx-feeds{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}
.csfx-feed{border:1px solid var(--line);border-radius:11px;padding:14px;background:#fff}
.csfx-feed-h{display:flex;align-items:center;justify-content:space-between;gap:8px}
.csfx-feed-name{font-weight:700;font-size:14px}
.csfx-feed-meta{font-size:11.5px;color:var(--muted);margin:6px 0 10px}
.csfx-catpill{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;padding:2px 7px;border-radius:50px}
.csfx-catpill.m{color:#991b1b;background:#fee2e2}.csfx-catpill.a{color:#92400e;background:#fef3c7}.csfx-catpill.b{color:#1e3a8a;background:#dbeafe}
.csfx-toggle{display:inline-flex;align-items:center;gap:10px;cursor:pointer;font-size:13px;font-weight:600;color:var(--ink);user-select:none}
.csfx-toggle input{position:absolute;opacity:0;width:0;height:0}
.csfx-track{position:relative;width:46px;height:26px;border-radius:50px;background:#dc2626;transition:background .18s;flex:0 0 auto}
.csfx-track:after{content:'';position:absolute;top:3px;left:3px;width:20px;height:20px;border-radius:50%;background:#fff;transition:transform .18s;box-shadow:0 1px 2px rgba(0,0,0,.35)}
.csfx-toggle input:checked + .csfx-track{background:#16a34a}
.csfx-toggle input:checked + .csfx-track:after{transform:translateX(20px)}
.csfx-toggle.big .csfx-track{width:54px;height:30px}.csfx-toggle.big .csfx-track:after{width:24px;height:24px}
.csfx-toggle.big input:checked + .csfx-track:after{transform:translateX(24px)}
.csfx-tlabel{min-width:64px;font-size:12.5px}
.csfx-tlabel .on{color:#16a34a}.csfx-tlabel .off{color:#dc2626}
</style>

<div class="csfx-head">
  <span class="mk">$shield</span>
  <span class="csfx-verlbl">v$ver</span>
  <div class="right">$under $statuspill</div>
</div>

$notices

<div class="csfx-tabs" id="csfx-tabs">
  <button class="csfx-tab" data-t="dashboard">Dashboard</button>
  <button class="csfx-tab" data-t="security">Security Level</button>
  <button class="csfx-tab" data-t="threatintel">Threat Intel</button>
  <button class="csfx-tab" data-t="malware">$sc_tab</button>
  <button class="csfx-tab" data-t="firewall">Firewall</button>
  <button class="csfx-tab" data-t="deny">Deny List ($nd)</button>
  <button class="csfx-tab" data-t="allow">Allow List ($na)</button>
  <button class="csfx-tab" data-t="temp">Temporary ($nt)</button>
  <button class="csfx-tab" data-t="lfd">LFD &amp; Events</button>
  <button class="csfx-tab" data-t="config">Configuration</button>
  <button class="csfx-tab" data-t="diag">Diagnostics</button>
  <button class="csfx-tab" data-t="update">Update$updot</button>
</div>

<!-- DASHBOARD -->
<div class="csfx-panel" data-p="dashboard">
  <div class="csfx-cards">
    <div class="csfx-card"><div class="k csfx-k-blue">$score<span style="font-size:15px">/100</span></div><div class="l">Protection score</div></div>
    <div class="csfx-card"><div class="k csfx-k-red">$nd</div><div class="l">Denied IPs</div></div>
    <div class="csfx-card"><div class="k csfx-k-amber">$nt</div><div class="l">Temporary blocks</div></div>
    <div class="csfx-card"><div class="k csfx-k-green">$na</div><div class="l">Allowed IPs</div></div>
    <div class="csfx-card"><div class="k">@{[ $enforcing ? 'On' : 'Test' ]}</div><div class="l">Enforcement</div></div>
    <div class="csfx-card"><div class="k @{[ $threat_level eq 'high' ? 'csfx-k-red' : ($threat_level eq 'elevated'?'csfx-k-amber':'csfx-k-green') ]}">\u$threat_level</div><div class="l">Threat level</div></div>
  </div>
  <div class="csfx-grid2">
    <div class="csfx-box"><h3>Quick action</h3>
      <form method="post"><input type="hidden" name="tab" value="dashboard">
        <div class="csfx-actions">
          <input type="text" name="ip" placeholder="IP or CIDR" size="20">
          <input type="text" name="comment" placeholder="comment (optional)" size="18">
          <button class="csfx-btn r" name="action" value="deny">Block</button>
          <button class="csfx-btn g" name="action" value="allow">Allow</button>
          <button class="csfx-btn o" name="action" value="unblock">Unblock</button>
        </div>
      </form>
      <form method="post" style="margin-top:10px"><input type="hidden" name="tab" value="dashboard">
        <button class="csfx-btn b" name="action" value="reload">Safe reload firewall</button>
      </form>
    </div>
    <div class="csfx-box"><h3>Recent LFD events</h3>
      <div style="max-height:220px;overflow:auto">$events_html</div>
    </div>
  </div>
</div>

<!-- FIREWALL -->
<div class="csfx-panel" data-p="firewall">
  <div class="csfx-box">
    <div class="csfx-fwhead">
      <h3 style="margin:0">Firewall control</h3>
      <span class="csfx-pill @{[ $tableok ? ($enforcing ? 'ok' : 'warn') : 'bad' ]}">@{[ $tableok ? ($enforcing ? 'Running &amp; Enforcing' : 'Running &middot; TESTING') : 'Stopped' ]}</span>
    </div>

    <div class="csfx-ctlbar">
      <form method="post"><input type="hidden" name="tab" value="firewall"><button class="csfx-ctl start" name="action" value="fw-start" data-confirm="Start the firewall: enable services and apply the ruleset?"><span class="csfx-ci">&#9654;</span> Start</button></form>
      <form method="post"><input type="hidden" name="tab" value="firewall"><button class="csfx-ctl restart" name="action" value="fw-restart" data-confirm="Restart the firewall now?"><span class="csfx-ci">&#8635;</span> Restart</button></form>
      <form method="post"><input type="hidden" name="tab" value="firewall"><button class="csfx-ctl stop" name="action" value="fw-stop" data-confirm="STOP the firewall? The nftables table will be removed and the server will be UNPROTECTED until you start it again."><span class="csfx-ci">&#9632;</span> Stop</button></form>
      <span class="csfx-ctlsep"></span>
      <form method="post"><input type="hidden" name="tab" value="firewall"><button class="csfx-btn b" name="action" value="reload">Reload (safe)</button></form>
      <form method="post"><input type="hidden" name="tab" value="firewall"><button class="csfx-btn o" name="action" value="flush">Flush temporary blocks</button></form>
    </div>

    $oplog_html

    <div class="csfx-statgrid">
      <div class="csfx-stat"><div class="csfx-stat-k">Mode</div><div class="csfx-stat-v">@{[ $enforcing ? '<span class="csfx-badge g">Enforcing</span>' : '<span class="csfx-badge a">TESTING</span>' ]}</div></div>
      <div class="csfx-stat"><div class="csfx-stat-k">Input policy</div><div class="csfx-stat-v"><span class="csfx-badge @{[ ($cfg{INPUT_POLICY}||'drop') eq 'drop' ? 'g' : 'a' ]}">@{[ esc(uc($cfg{INPUT_POLICY}||'drop')) ]}</span></div></div>
      <div class="csfx-stat"><div class="csfx-stat-k">nftables table</div><div class="csfx-stat-v">@{[ $tableok ? '<span class="csfx-badge g">inet csf loaded</span>' : '<span class="csfx-badge r">not loaded</span>' ]}</div></div>
      <div class="csfx-stat"><div class="csfx-stat-k">IPv6</div><div class="csfx-stat-v">@{[ $cfg{IPV6} ? '<span class="csfx-badge g">first-class</span>' : '<span class="csfx-badge a">off</span>' ]}</div></div>
    </div>

    <div class="csfx-ports">
      <div class="csfx-porthead">Open ports</div>
      <div class="csfx-portrow"><span class="csfx-portlbl">TCP in</span><span class="csfx-portval">@{[ port_chips($tcp_in) ]}</span></div>
      <div class="csfx-portrow"><span class="csfx-portlbl">TCP out</span><span class="csfx-portval">@{[ port_chips($tcp_out) ]}</span></div>
      <div class="csfx-portrow"><span class="csfx-portlbl">UDP in</span><span class="csfx-portval">@{[ port_chips($udp_in) ]}</span></div>
      <div class="csfx-portrow"><span class="csfx-portlbl">UDP out</span><span class="csfx-portval">@{[ port_chips($udp_out) ]}</span></div>
      <div class="csfx-porthint">Edit ports in the <b>Configuration</b> tab, then Reload.</div>
    </div>
  </div>

  <!-- Cloudflare integration -->
  <div class="csfx-box csfx-cf @{[ $cf_on ? 'on' : '' ]}">
    <div class="csfx-cfrow">
      <div class="csfx-cflogo">$CF_LOGO</div>
      <div class="csfx-cfbody">
        <div class="csfx-cftitle">Cloudflare edge allowlist <span class="csfx-pill @{[ $cf_on ? 'ok' : 'warn' ]}">@{[ $cf_on ? "On &middot; $cf_count ranges" : 'Off' ]}</span></div>
        <p class="csfx-muted" style="margin:6px 0 0;font-size:13px">Add every Cloudflare edge IP range to the allow list so visitor traffic proxied through Cloudflare is never blocked by LFD. Ranges are fetched live from Cloudflare and tagged <code>Cloudflare</code> in your Allow List.</p>
      </div>
      <div class="csfx-cfact">
        @{[ $cf_on
          ? '<form method="post"><input type="hidden" name="tab" value="firewall"><button class="csfx-btn o" name="action" value="cf-enable">Refresh ranges</button></form><form method="post" style="margin-top:8px"><input type="hidden" name="tab" value="firewall"><button class="csfx-btn r" name="action" value="cf-disable" data-confirm="Remove all Cloudflare ranges from the allow list?">Disable</button></form>'
          : '<form method="post"><input type="hidden" name="tab" value="firewall"><button class="csfx-btn cf" name="action" value="cf-enable">Enable Cloudflare</button></form>' ]}
      </div>
    </div>
  </div>
</div>

<!-- SECURITY LEVEL -->
<div class="csfx-panel" data-p="security">
  <div class="csfx-box">
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:6px">
      <h3 style="margin:0">Security level</h3>
      <span class="csfx-pill @{[ $active_profile eq 'attack' ? 'bad' : ($active_profile ? 'ok' : 'warn') ]}">Active: $active_label</span>
    </div>
    <p class="csfx-muted" style="margin:0 0 16px;font-size:13.5px">One-click presets that tune how aggressively the firewall detects and blocks. They adjust risk thresholds, reputation memory and logging &mdash; they never change your open ports or enforcement mode. After applying, reload the firewall (Firewall tab) and restart LFD so the new thresholds take effect.</p>
    <div class="csfx-profs">$profiles_html</div>
  </div>
</div>

<!-- THREAT INTELLIGENCE -->
<div class="csfx-panel" data-p="threatintel">
  <div class="csfx-box">
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:6px">
      <h3 style="margin:0">Threat Intelligence</h3>
      <span class="csfx-pill @{[ $ti_on ? 'ok' : 'warn' ]}">@{[ $ti_on ? 'Enabled' : 'Disabled' ]}</span>
      <span class="csfx-count">Last update: $ti_updated &middot; $ti_total indicators loaded</span>
    </div>
    <p class="csfx-muted" style="margin:0 0 14px;font-size:13.5px">Automatically downloads reputable IP/CIDR reputation feeds into dedicated nftables sets &mdash; never into your deny list. <b>High</b> (Spamhaus DROP) blocks inbound + outbound; <b>botnet</b> (Feodo C2) blocks outbound; <b>attackers</b> (CINS/IPsum/Blocklist.de) blocks inbound. Feeds refresh hourly via cron.</p>
    <form method="post"><input type="hidden" name="tab" value="threatintel">
      <div class="csfx-ti-master">
        <label class="csfx-toggle big"><input type="checkbox" name="TI_ENABLE" value="1"@{[ $ti_on ? ' checked' : '' ]}><span class="csfx-track"></span><span class="csfx-tlabel" style="min-width:0;font-size:15px;font-weight:700">Enable Threat Intelligence</span></label>
      </div>
      <div class="csfx-feeds">$ti_feeds_html</div>
      <div class="csfx-savebar">
        <button class="csfx-btn b" name="action" value="ti-save">Save feed selection</button>
        <button class="csfx-btn g" name="action" value="ti-update">Update feeds now</button>
        <span class="csfx-muted">After changing feeds, reload the firewall (Firewall tab) then update.</span>
      </div>
    </form>
  </div>
</div>

<!-- MALWARE SCAN -->
<div class="csfx-panel" data-p="malware">
  <div class="csfx-box">
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:6px">
      <h3 style="margin:0">Malicious upload scanning</h3>
      $sc_pill
      <span class="csfx-count">Last scan: $sc_last &middot; Signatures: $sc_sigs</span>
    </div>
    <p class="csfx-muted" style="margin:0 0 12px;font-size:13.5px">Every 5 minutes the website files that changed are scanned with <b>ClamAV</b> + the <b>rfxn</b> (Linux Malware Detect) web-malware signatures, <b>YARA</b> (rfxn + YARA-Forge) and built-in checks. Files matching a web-malware signature are moved to quarantine and their uploader is blocked for 24 hours when the FTP or web log names one clear IP. Built-in heuristic findings are only logged.</p>
    <p style="margin:0 0 14px;font-size:13.5px">Engines: $sc_eng</p>
    @{[ $sc_ready ? '' : '<div class="csfx-ti-master" style="margin-bottom:14px"><form method="post" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap"><input type="hidden" name="tab" value="malware"><b>Not set up yet.</b><span class="csfx-muted">Installs ClamAV and YARA from your OS repositories, downloads the signatures and turns scanning on.</span><button class="csfx-btn g" name="action" value="scan-setup" data-confirm="Install ClamAV and YARA and download malware signatures now?">Set up scanning</button></form></div>' ]}
    @{[ ($sst->{imunify} && !$cfg{SCAN_FORCE}) ? '<p class="csfx-muted" style="margin:0 0 14px;font-size:13px"><b>Imunify360 is installed</b> and already scans uploads, so CSF scanning stands by (set <code>SCAN_FORCE = "1"</code> in csf.conf to run both).</p>' : '' ]}
    <form method="post"><input type="hidden" name="tab" value="malware">
      <div class="csfx-ti-master" style="display:grid;gap:12px">
        <label class="csfx-toggle big"><input type="checkbox" name="SCAN_ENABLE" value="1"@{[ $sc_on ? ' checked' : '' ]}><span class="csfx-track"></span><span class="csfx-tlabel" style="min-width:0;font-size:15px;font-weight:700">Scan uploaded files</span></label>
        <label style="font-size:13.5px">When malware is found:
          <select name="SCAN_ACTION" style="margin-left:6px">
            <option value="quarantine"@{[ ($cfg{SCAN_ACTION} // 'quarantine') ne 'alert' ? ' selected' : '' ]}>Move it to quarantine (recommended)</option>
            <option value="alert"@{[ ($cfg{SCAN_ACTION} // '') eq 'alert' ? ' selected' : '' ]}>Only alert, leave the file</option>
          </select></label>
        <label class="csfx-toggle"><input type="checkbox" name="SCAN_BLOCK_UPLOADER" value="1"@{[ ($cfg{SCAN_BLOCK_UPLOADER} // 1) ? ' checked' : '' ]}><span class="csfx-track"></span><span class="csfx-tlabel" style="min-width:0">Block the uploader's IP for 24 hours (only when one clear IP is found)</span></label>
        <label style="font-size:13.5px">Alert email: <input type="text" name="SCAN_ALERT_TO" value="$sc_alert_to" placeholder="$sc_alert_default" size="34" style="margin-left:6px"> <span class="csfx-muted">empty = $sc_alert_default &middot; "none" = no email</span></label>
      </div>
      <div class="csfx-savebar">
        <button class="csfx-btn b" name="action" value="scan-save">Save settings</button>
        <button class="csfx-btn g" name="action" value="scan-now">Scan changed files now</button>
        <button class="csfx-btn o" name="action" value="scan-update">Update signatures</button>
      </div>
    </form>
    $sc_setup_html
  </div>
  <div class="csfx-box"><h3>Quarantine ($nq)</h3>
    <p class="csfx-muted" style="margin:0 0 12px;font-size:13px">Quarantined files are removed from the website and kept unreadable in <code>/var/lib/csf/quarantine</code>. Restore puts a file back exactly as it was (owner, permissions, date).</p>
    <div style="overflow:auto">$q_html</div>
  </div>
  <div class="csfx-box"><h3>Recent scan activity</h3>$sc_log_html
    <p class="csfx-muted" style="margin:10px 0 0;font-size:12.5px">Scanned folders:<br>$sc_roots</p>
  </div>
</div>

<!-- DENY / ALLOW / TEMP tables (client-side) -->
<div class="csfx-panel" data-p="deny">
  <div class="csfx-box"><h3>Blocked IP addresses</h3>
    <form method="post" style="margin-bottom:14px"><input type="hidden" name="tab" value="deny">
      <div class="csfx-actions"><input type="text" name="ip" placeholder="IP or CIDR to block" size="20"><input type="text" name="comment" placeholder="comment" size="18"><button class="csfx-btn r" name="action" value="deny">Block</button></div>
    </form>
    <div class="csfx-tools"><input type="text" id="csfx-deny-q" placeholder="Search denied IPs / notes..."><span class="csfx-count" id="csfx-deny-count"></span></div>
    <div id="csfx-deny-tbl"></div><div class="csfx-pg" id="csfx-deny-pg"></div>
  </div>
</div>
<div class="csfx-panel" data-p="allow">
  <div class="csfx-box"><h3>Allowed IP addresses</h3>
    <form method="post" style="margin-bottom:14px"><input type="hidden" name="tab" value="allow">
      <div class="csfx-actions"><input type="text" name="ip" placeholder="IP or CIDR to allow" size="20"><input type="text" name="comment" placeholder="comment" size="18"><button class="csfx-btn g" name="action" value="allow">Allow</button></div>
    </form>
    <div class="csfx-tools"><input type="text" id="csfx-allow-q" placeholder="Search allowed IPs / notes..."><span class="csfx-count" id="csfx-allow-count"></span></div>
    <div id="csfx-allow-tbl"></div><div class="csfx-pg" id="csfx-allow-pg"></div>
  </div>
</div>
<div class="csfx-panel" data-p="temp">
  <div class="csfx-box"><h3>Temporary entries</h3>
    <form method="post" style="margin-bottom:14px"><input type="hidden" name="tab" value="temp">
      <div class="csfx-actions"><input type="text" name="ip" placeholder="IP" size="18"><input type="text" name="ttl" placeholder="seconds" size="8" value="3600"><input type="text" name="comment" placeholder="comment" size="14"><button class="csfx-btn r" name="action" value="tempdeny">Temp block</button><button class="csfx-btn g" name="action" value="tempallow">Temp allow</button></div>
    </form>
    <div class="csfx-tools"><input type="text" id="csfx-temp-q" placeholder="Search temporary entries..."><span class="csfx-count" id="csfx-temp-count"></span></div>
    <div id="csfx-temp-tbl"></div><div class="csfx-pg" id="csfx-temp-pg"></div>
  </div>
</div>

<!-- LFD -->
<div class="csfx-panel" data-p="lfd">
  <div class="csfx-box"><h3>LFD 2.0 events (most recent)</h3><div style="max-height:420px;overflow:auto">$events_html</div></div>
</div>

<!-- CONFIG -->
<div class="csfx-panel" data-p="config">
  <div class="csfx-box">
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px">
      <h3 style="margin:0">Firewall configuration</h3>
      <span class="csfx-count">$cfg_count settings &middot; edits to /etc/csf/csf.conf</span>
    </div>
    <div class="csfx-tools"><input type="text" id="csfx-cfg-q" placeholder="Search settings (e.g. TCP_IN, LF_SSHD, cluster)..."><span class="csfx-count" id="csfx-cfg-count"></span></div>
    <form method="post"><input type="hidden" name="tab" value="config">
      <div id="csfx-cfg-list">$config_html</div>
      <div class="csfx-savebar">
        <button class="csfx-btn b" name="action" value="saveconfig">Save configuration</button>
        <span class="csfx-muted">Port / policy changes take effect after a firewall reload (Firewall tab).</span>
      </div>
    </form>
  </div>
</div>

<!-- DIAG -->
<div class="csfx-panel" data-p="diag">
  <div class="csfx-cards">
    <div class="csfx-card"><div class="k @{[ $tableok ? 'csfx-k-green' : 'csfx-k-red' ]}">@{[ $tableok ? 'OK' : 'Down' ]}</div><div class="l">nftables table</div></div>
    <div class="csfx-card"><div class="k @{[ $enforcing ? 'csfx-k-green' : 'csfx-k-amber' ]}">@{[ $enforcing ? 'On' : 'Test' ]}</div><div class="l">Enforcement</div></div>
    <div class="csfx-card"><div class="k csfx-k-red">$nd</div><div class="l">Denied IPs</div></div>
    <div class="csfx-card"><div class="k csfx-k-green">$na</div><div class="l">Allowed IPs</div></div>
    <div class="csfx-card"><div class="k @{[ $cf_on ? 'csfx-k-blue' : '' ]}">$cf_count</div><div class="l">Cloudflare ranges</div></div>
    <div class="csfx-card"><div class="k @{[ $update_avail ? 'csfx-k-amber' : 'csfx-k-green' ]}">@{[ $update_avail ? 'New' : 'Latest' ]}</div><div class="l">Version $ver</div></div>
  </div>

  <div class="csfx-box csfx-tests">
    <div class="csfx-fwhead"><h3 style="margin:0">Administrator tests</h3></div>
    <p class="csfx-muted" style="margin:0 0 12px;font-size:13px">Run an end-to-end functional check: confirms the kernel table is loaded, that a blocked IP actually reaches the nftables set, and that the csf/lfd services are active and boot-persistent.</p>
    <div class="csfx-actions">
      <form method="post"><input type="hidden" name="tab" value="diag"><button class="csfx-btn b" name="action" value="run-selftest">&#9654; Run self-test</button></form>
      <form method="post"><input type="hidden" name="tab" value="diag"><button class="csfx-btn o" name="action" value="reload">Reload &amp; validate ruleset</button></form>
    </div>
    $oplog_html
  </div>

  <div class="csfx-grid2">
    <div class="csfx-box"><h3>System health</h3>$health_html</div>
    <div class="csfx-box"><h3>@{[ $cpsum->{cpanel} ? 'cPanel &amp; environment' : 'Platform &amp; environment' ]}</h3>
      @{[ env_rows($cpv) ]}
      <div class="csfx-hrow"><span class="csfx-dot @{[ $cfg{IPV6}?'ok':'warn' ]}"></span><b>IPv6</b><span class="csfx-muted">@{[ $cfg{IPV6}?'first-class':'disabled' ]}</span></div>
      <div class="csfx-hrow"><span class="csfx-dot @{[ $cf_on?'ok':'warn' ]}"></span><b>Cloudflare</b><span class="csfx-muted">@{[ $cf_on?"allowlisted ($cf_count ranges)":'not enabled' ]}</span></div>
      <div class="csfx-hrow"><span class="csfx-dot @{[ $tableok?'ok':'bad' ]}"></span><b>nftables table</b><span class="csfx-muted">@{[ $tableok?'inet csf loaded':'not loaded' ]}</span></div>
    </div>
  </div>
</div>

<!-- UPDATE -->
<div class="csfx-panel" data-p="update">
  <div class="csfx-box">
    <h3>Software updates</h3>
    <div class="csfx-uprow">
      <div class="csfx-upcol">
        <div class="csfx-upk">Installed version</div>
        <div class="csfx-upv">v$ver</div>
      </div>
      <div class="csfx-upcol">
        <div class="csfx-upk">Latest release</div>
        <div class="csfx-upv" id="csfx-uplatest">$uplatest</div>
      </div>
      <div class="csfx-upcol">
        <div class="csfx-upk">Status</div>
        <div class="csfx-upv" id="csfx-upstatus">$upstate</div>
      </div>
    </div>

    <div class="csfx-upbar-wrap" id="csfx-upbar-wrap" style="display:none">
      <div class="csfx-upbar"><div class="csfx-upbar-fill" id="csfx-upbar-fill"></div></div>
      <div class="csfx-upmsg" id="csfx-upmsg">Preparing&hellip;</div>
    </div>

    <div class="csfx-actions" style="margin-top:16px">
      <form method="post" id="csfx-upform"><input type="hidden" name="tab" value="update">
        <button class="csfx-btn b" name="action" value="do-update" id="csfx-upbtn"$updisabled>$upbtnlabel</button>
      </form>
      <a class="csfx-btn o" href="https://shield.underhost.com/firewall/" target="_blank" rel="noopener">Release notes</a>
    </div>
    <p class="csfx-muted" style="margin-top:14px;font-size:12.5px">
      Updates are downloaded directly from <b>shield.underhost.com</b>, checksum-verified (SHA-256),
      then installed in place. Your configuration, deny/allow lists and Threat Intel sets are preserved.
      The firewall is reloaded automatically when the update completes.
    </p>
  </div>
</div>

<div class="csfx-foot">
  <div class="csfx-foot-l">
    <div class="t"><b>Core Shield Firewall</b><span class="v">CSF v$ver</span></div>
    <div class="sub">GNU GPL v3 &middot; a next-generation fork of ConfigServer Security &amp; Firewall</div>
  </div>
  <div class="csfx-foot-r">
    <span class="pb">Powered by <a href="https://underhost.com/" target="_blank" rel="noopener" class="csfx-uhlink">UnderHost.com</a></span>
  </div>
</div>
</div>

<script>
(function(){
  var root=document.getElementById('csfx'); if(!root) return;
  var DENY=[$deny_json], ALLOW=[$allow_json], TEMP=[$temp_json];
  var tabs=root.querySelectorAll('.csfx-tab'), panels=root.querySelectorAll('.csfx-panel');
  function show(t){ tabs.forEach(function(b){b.classList.toggle('active',b.dataset.t===t)});
    panels.forEach(function(p){p.classList.toggle('active',p.dataset.p===t)});
    try{ if(history.replaceState) history.replaceState(null,'',location.pathname+location.search+'#'+t); }catch(e){} }
  tabs.forEach(function(b){ b.addEventListener('click',function(){show(b.dataset.t)}); });
  var initial=(location.hash||'').replace('#','') || '$active_tab' || 'dashboard';
  if(!root.querySelector('.csfx-tab[data-t="'+initial+'"]')) initial='dashboard';
  show(initial);

  // confirm-gated buttons (firewall stop/start/restart, cloudflare disable)
  root.querySelectorAll('button[data-confirm]').forEach(function(b){
    b.addEventListener('click',function(e){ if(!window.confirm(b.getAttribute('data-confirm'))){ e.preventDefault(); } });
  });

  // "Update now" banner button -> jump to the Update tab
  root.querySelectorAll('[data-goupdate]').forEach(function(b){
    b.addEventListener('click',function(){ show('update'); var u=document.getElementById('csfx-upbtn'); if(u) u.scrollIntoView({behavior:'smooth',block:'center'}); });
  });

  // --- live update progress bar (AJAX polling, no full-page reload loop) ---
  (function(){
    var wrap=document.getElementById('csfx-upbar-wrap'), fill=document.getElementById('csfx-upbar-fill'),
        msg=document.getElementById('csfx-upmsg'), st=document.getElementById('csfx-upstatus'),
        btn=document.getElementById('csfx-upbtn'), poll=null;
    if(!wrap) return;
    // justUpdate is 1 only on the request that kicked off an update this session.
    var justUpdate = $just_update, sawRunning = !!justUpdate;
    var base=location.pathname+(location.search?location.search+'&':'?')+'action=update-progress';
    function setPct(p,cls){ wrap.style.display='block'; fill.className='csfx-upbar-fill'+(cls?' '+cls:''); fill.style.width=Math.max(0,Math.min(100,p))+'%'; }
    function stop(){ if(poll){clearInterval(poll);poll=null;} }
    function tick(){
      fetch(base,{cache:'no-store',credentials:'same-origin'}).then(function(r){return r.text();}).then(function(t){
        var m=(t||'').split('|'), pct=parseInt(m[0],10); var txt=m.slice(1).join('|')||'';
        if(isNaN(pct)) return;
        if(pct<0){ setPct(100,'err'); msg.textContent=txt||'Update failed'; if(st)st.innerHTML='<span class="csfx-pill bad">Failed</span>'; if(btn)btn.disabled=false; stop(); return; }
        if(pct>0 && pct<100){ sawRunning=true; if(btn)btn.disabled=true; setPct(pct); msg.textContent=txt||('Working ('+pct+'%)'); return; }
        if(pct>=100){
          setPct(100); msg.textContent=txt||'Update complete';
          if(sawRunning){ if(st)st.innerHTML='<span class="csfx-pill ok">Updated - reloading</span>'; stop(); setTimeout(function(){location.reload();},2500); }
          else { stop(); }   // stale/idle 100 from a past run -> show nothing new, never reload
        }
      }).catch(function(){});
    }
    function start(){ if(poll)return; tick(); poll=setInterval(tick,1500); }
    // Probe once; only begin polling if an update is actually in progress
    // (a stale "100" must not start polling or trigger a reload).
    function probe(){
      fetch(base,{cache:'no-store',credentials:'same-origin'}).then(function(r){return r.text();}).then(function(t){
        var pct=parseInt((t||'').split('|')[0],10);
        if(!isNaN(pct) && pct>0 && pct<100) start();
      }).catch(function(){});
    }
    if(justUpdate){ start(); }                 // we just clicked Update -> follow it to completion
    else if(initial==='update'){ probe(); }    // opened the tab -> only follow a live run
    var tabbtn=document.querySelector('.csfx-tab[data-t="update"]');
    if(tabbtn) tabbtn.addEventListener('click', probe);
  })();

  function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
  function mkTable(data, ids, act){
    var q=document.getElementById(ids.q), tbl=document.getElementById(ids.tbl), pg=document.getElementById(ids.pg),
        cnt=document.getElementById(ids.count), page=1, per=50, term='';
    function filtered(){ if(!term) return data; var t=term.toLowerCase();
      return data.filter(function(r){return (r.ip+' '+(r.note||'')).toLowerCase().indexOf(t)>=0;}); }
    function render(){
      var d=filtered(), pages=Math.max(1,Math.ceil(d.length/per)); if(page>pages)page=pages;
      var start=(page-1)*per, rows=d.slice(start,start+per);
      var h='<table class="csfx-tbl"><thead><tr><th>IP / CIDR</th><th>Reason / note</th><th></th></tr></thead><tbody>';
      if(!rows.length){ h+='<tr><td colspan="3" class="csfx-muted">'+(data.length?'No matches.':'None.')+'</td></tr>'; }
      rows.forEach(function(r){
        h+='<tr><td class="ip">'+esc(r.ip)+'</td><td>'+r.note+'</td><td style="text-align:right">'+
           '<form method="post" style="margin:0"><input type="hidden" name="tab" value="'+ids.tab+'">'+
           '<input type="hidden" name="ip" value="'+esc(r.ip)+'"><button class="csfx-btn mini" name="action" value="'+act+'">remove</button></form></td></tr>';
      });
      h+='</tbody></table>'; tbl.innerHTML=h;
      cnt.textContent=d.length+(term?(' of '+data.length):'')+' entr'+(d.length===1?'y':'ies');
      var pgh=''; if(pages>1){ pgh='<button '+(page<=1?'disabled':'')+' data-a="prev">Prev</button>'+
        '<span class="csfx-count">Page '+page+' / '+pages+'</span>'+
        '<button '+(page>=pages?'disabled':'')+' data-a="next">Next</button>'; }
      pg.innerHTML=pgh;
      pg.querySelectorAll('button').forEach(function(b){ b.addEventListener('click',function(){
        if(b.dataset.a==='prev'&&page>1)page--; if(b.dataset.a==='next'&&page<pages)page++; render(); }); });
    }
    if(q) q.addEventListener('input',function(){term=q.value;page=1;render();});
    render();
  }
  mkTable(DENY, {q:'csfx-deny-q',tbl:'csfx-deny-tbl',pg:'csfx-deny-pg',count:'csfx-deny-count',tab:'deny'}, 'undeny');
  mkTable(ALLOW,{q:'csfx-allow-q',tbl:'csfx-allow-tbl',pg:'csfx-allow-pg',count:'csfx-allow-count',tab:'allow'}, 'unallow');
  mkTable(TEMP, {q:'csfx-temp-q',tbl:'csfx-temp-tbl',pg:'csfx-temp-pg',count:'csfx-temp-count',tab:'temp'}, 'temprm');

  // threat-intel toggles: flip the ON/OFF label live
  root.querySelectorAll('.csfx-toggle input[type=checkbox]').forEach(function(inp){
    inp.addEventListener('change',function(){
      var lbl=inp.parentNode.querySelector('.csfx-tlabel');
      if(lbl && lbl.querySelector('.on,.off')) lbl.innerHTML = inp.checked ? '<span class="on">ON</span>' : '<span class="off">OFF</span>';
    });
  });
  // config editor: segmented Off/On highlight
  root.querySelectorAll('.csfx-seg').forEach(function(seg){
    seg.addEventListener('change',function(){
      seg.querySelectorAll('label').forEach(function(l){
        var r=l.querySelector('input'); l.classList.toggle('sel', r && r.checked);
      });
    });
  });
  // config editor: live search across settings
  var cq=document.getElementById('csfx-cfg-q'), clist=document.getElementById('csfx-cfg-list'), ccount=document.getElementById('csfx-cfg-count');
  if(cq && clist){
    var rows=clist.querySelectorAll('.csfx-cfg'), secs=clist.querySelectorAll('.csfx-sec');
    function cfilter(){
      var t=cq.value.toLowerCase().trim(), shown=0;
      rows.forEach(function(r){ var m=!t||(r.dataset.k||'').indexOf(t)>=0; r.style.display=m?'':'none'; if(m)shown++; });
      secs.forEach(function(s){ var any=s.querySelector('.csfx-cfg:not([style*="none"])'); s.style.display=any?'':'none'; });
      ccount.textContent=shown+' setting'+(shown===1?'':'s')+(t?' matched':'');
    }
    cq.addEventListener('input',cfilter); cfilter();
  }
})();
</script>
HTML
}

# UnderShield logo (official two-colour wordmark, CSF2::Brand)
sub under_wordmark {
    require CSF2::Brand;
    return '<span class="csfx-under">' . CSF2::Brand::undershield_img(22) . '</span>';
}

sub shield_svg {
    return q{<svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="cs" x1="12" y1="4" x2="52" y2="60" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#6b78ff"/><stop offset=".5" stop-color="#5865f2"/><stop offset="1" stop-color="#2b2f80"/></linearGradient><path id="cp" d="M32 3.5 L55 11 V31.2 C55 45.4 45.2 54.2 32 60.5 C18.8 54.2 9 45.4 9 31.2 V11 Z"/><clipPath id="cc"><use href="#cp"/></clipPath></defs><use href="#cp" fill="url(#cs)"/><g clip-path="url(#cc)" fill="#2c3382"><rect x="12" y="20" width="11.5" height="6.4" rx="1.6"/><rect x="25.2" y="20" width="11.5" height="6.4" rx="1.6"/><rect x="38.4" y="20" width="11.5" height="6.4" rx="1.6"/><rect x="5.6" y="28" width="11.5" height="6.4" rx="1.6"/><rect x="18.6" y="28" width="11.5" height="6.4" rx="1.6"/><rect x="31.8" y="28" width="11.5" height="6.4" rx="1.6"/><rect x="45" y="28" width="11.5" height="6.4" rx="1.6"/><rect x="25.2" y="36" width="11.5" height="6.4" rx="1.6"/><rect x="38.4" y="36" width="11.5" height="6.4" rx="1.6"/></g><rect x="12" y="36" width="11.5" height="6.4" rx="1.6" fill="#35ed7e" clip-path="url(#cc)"/><use href="#cp" fill="none" stroke="#fff" stroke-opacity=".14" stroke-width="1.4"/></svg>};
}
