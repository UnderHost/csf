package CSF2::UIAuth;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::UIAuth - login for the standalone web UI (servers without WHM).
#
# Under WHM the plugin is protected by WHM's own login. Everywhere else the UI
# is served by csf2-ui, and this module is the whole security boundary:
#   - users      : /etc/csf/ui.users  "user:sha512crypt:totp_base32" (0600)
#   - passwords  : SHA-512 crypt, 100k rounds, constant-time compare
#   - 2FA        : TOTP (RFC 6238, SHA-1, 6 digits, 30s), +/-1 step, no replay
#   - sessions   : random 256-bit token in a cookie; only its SHA-256 is stored
#                  under $var/ui-sessions; idle + absolute expiry; CSRF token
#   - throttling : per-IP failure counter; locked after too many failures
#
# Core Perl only (Digest::SHA, MIME::Base64), so it runs on any distro perl.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use Digest::SHA qw(sha256_hex hmac_sha1);
use Fcntl qw(:DEFAULT :flock);

our $ROUNDS        = 100000;
our $IDLE_SECONDS  = 1800;       # 30 min without a request ends the session
our $MAX_SECONDS   = 43200;      # 12 h absolute session lifetime
our $FAIL_LIMIT    = 5;          # failures per IP ...
our $FAIL_WINDOW   = 900;        # ... within 15 min => locked for the window
our $FAIL_GLOBAL   = 50;         # failures from all addresses together in the window
                                 # => sign-in paused for everyone (distributed guessing)

sub new {
    my ($class, %o) = @_;
    my $self = {
        etc => $o{etc} || '/etc/csf',
        var => $o{var} || '/var/lib/csf',
        rounds => $o{rounds} || $ROUNDS,
        now => $o{now},          # injectable clock for tests
    };
    return bless $self, $class;
}

sub _now   { my $s = shift; return defined $s->{now} ? $s->{now} : time }
sub _users { return $_[0]{etc} . '/ui.users' }
sub _sdir  { return $_[0]{var} . '/ui-sessions' }

###############################################################################
# randomness
sub random_bytes {
    my ($n) = @_;
    my $buf = '';
    if (open my $fh, '<:raw', '/dev/urandom') { read($fh, $buf, $n); close $fh }
    die "no /dev/urandom\n" unless length($buf) == $n;
    return $buf;
}
sub random_hex { return unpack('H*', random_bytes($_[0] || 32)) }

# constant-time string compare
sub ct_eq {
    my ($a, $b) = @_;
    return 0 unless defined $a && defined $b && length($a) == length($b);
    my $r = 0;
    $r |= ord(substr($a, $_, 1)) ^ ord(substr($b, $_, 1)) for 0 .. length($a) - 1;
    return $r == 0 ? 1 : 0;
}

###############################################################################
# passwords
sub hash_password {
    my ($s, $pw) = @_;
    my @c = ('.', '/', 0..9, 'A'..'Z', 'a'..'z');
    my $salt = join '', map { $c[ord($_) % 64] } split //, random_bytes(16);
    my $h = crypt($pw, '$6$rounds=' . $s->{rounds} . '$' . $salt . '$');
    die "SHA-512 crypt not supported by this system\n" unless defined $h && $h =~ /^\$6\$/;
    return $h;
}

sub check_password {
    my ($s, $pw, $hash) = @_;
    return 0 unless defined $pw && defined $hash && $hash =~ /^\$6\$/;
    my $got = crypt($pw, $hash);
    return ct_eq($got, $hash);
}

###############################################################################
# TOTP (RFC 6238)
my @B32 = ('A'..'Z', '2'..'7');
sub base32_encode {
    my ($bytes) = @_;
    my $bits = unpack('B*', $bytes);
    $bits .= '0' x ((5 - length($bits) % 5) % 5);
    return join '', map { $B32[oct("0b$_")] } ($bits =~ /(.{5})/g);
}
sub base32_decode {
    my ($str) = @_;
    $str = uc($str // ''); $str =~ s/[\s=-]//g;
    return undef if $str eq '' || $str =~ /[^A-Z2-7]/;
    my %v; @v{@B32} = (0 .. 31);
    my $bits = join '', map { sprintf '%05b', $v{$_} } split //, $str;
    $bits = substr($bits, 0, length($bits) - length($bits) % 8);
    return pack('B*', $bits);
}

sub new_totp_secret { return base32_encode(random_bytes(20)) }

# totp_code($secret_b32, $time) -> 6-digit string
sub totp_code {
    my ($secret, $t, $step) = @_;
    my $key = base32_decode($secret);
    return undef unless defined $key;
    my $counter = int(($t // time) / ($step || 30));
    my $msg = pack('NN', int($counter / 4294967296), $counter % 4294967296);
    my $h = hmac_sha1($msg, $key);
    my $off = ord(substr($h, -1)) & 0x0f;
    my $bin = unpack('N', substr($h, $off, 4)) & 0x7fffffff;
    return sprintf('%06d', $bin % 1_000_000);
}

# check_totp($user, $secret, $code) -> 1 | 0
# Accepts the previous/current/next 30s step; a used step can never be reused.
sub check_totp {
    my ($s, $user, $secret, $code) = @_;
    return 0 unless defined $code && $code =~ /^\d{6}$/;
    my $now = $s->_now;
    my $last = $s->_last_step($user);
    for my $d (-1, 0, 1) {
        my $t = $now + $d * 30;
        my $step = int($t / 30);
        next if defined $last && $step <= $last;      # replay
        if (ct_eq(totp_code($secret, $t), $code)) { $s->_last_step($user, $step); return 1 }
    }
    return 0;
}

sub _last_step {
    my ($s, $user, $set) = @_;
    my $dir = $s->_sdir; mkdir $dir, 0700 unless -d $dir;
    (my $safe = $user) =~ s/[^A-Za-z0-9_.-]//g;
    my $f = "$dir/totp-$safe";
    if (defined $set) { if (open my $fh, '>', $f) { print {$fh} "$set\n"; close $fh; chmod 0600, $f } return $set }
    return undef unless open my $fh, '<', $f;
    my $v = <$fh>; close $fh; chomp $v if defined $v;
    return (defined $v && $v =~ /^\d+$/) ? $v : undef;
}

sub otpauth_uri {
    my ($s, $user, $secret, $host) = @_;
    my $label = 'CSF:' . $user . '@' . ($host || 'server');
    $label =~ s/([^A-Za-z0-9:@._-])/sprintf('%%%02X', ord $1)/ge;
    return "otpauth://totp/$label?secret=$secret&issuer=CSF%20Firewall&digits=6&period=30";
}

###############################################################################
# users file
sub load_users {
    my ($s) = @_;
    my %u;
    open my $fh, '<', $s->_users or return {};
    while (my $l = <$fh>) {
        chomp $l; next if $l =~ /^\s*(#|$)/;
        my ($name, $hash, $totp) = split /:/, $l, 3;
        next unless defined $name && $name =~ /^[A-Za-z0-9_.-]{1,32}$/;
        $u{$name} = { hash => $hash, totp => $totp };
    }
    close $fh;
    return \%u;
}

sub save_users {
    my ($s, $u) = @_;
    my $f = $s->_users;
    my $tmp = "$f.tmp.$$";
    sysopen(my $fh, $tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600) or return (0, "open $tmp: $!");
    print {$fh} "# CSF standalone UI users - user:sha512crypt:totp_secret (managed by csf --ui-user)\n";
    print {$fh} join(':', $_, $u->{$_}{hash}, $u->{$_}{totp} // '') . "\n" for sort keys %$u;
    close $fh;
    chmod 0600, $tmp;
    rename($tmp, $f) or do { unlink $tmp; return (0, "rename: $!") };
    return (1, 'saved');
}

# set_user($name, $password) -> ($ok, $msg, $totp_secret)
# Creates or resets a user. A fresh TOTP secret is issued every time.
sub set_user {
    my ($s, $name, $pw) = @_;
    return (0, 'invalid user name (A-Z a-z 0-9 _ . - , max 32)') unless defined $name && $name =~ /^[A-Za-z0-9_.-]{1,32}$/;
    return (0, 'password must be at least 12 characters') unless defined $pw && length($pw) >= 12;
    my $u = $s->load_users;
    my $secret = new_totp_secret();
    $u->{$name} = { hash => $s->hash_password($pw), totp => $secret };
    my ($ok, $m) = $s->save_users($u);
    $s->_last_step($name, 0) if $ok;   # reset replay marker for the new secret
    return ($ok, $ok ? "user $name saved" : $m, $secret);
}

sub del_user {
    my ($s, $name) = @_;
    my $u = $s->load_users;
    return (0, "no such user: $name") unless $u->{$name};
    delete $u->{$name};
    $s->revoke_user_sessions($name);
    return $s->save_users($u);
}

###############################################################################
# login(user, password, code, ip) -> ($ok, $reason)
sub login {
    my ($s, $user, $pw, $code, $ip) = @_;
    return (0, 'locked') if $s->is_locked($ip);
    my $u = $s->load_users;
    my $rec = (defined $user) ? $u->{$user} : undef;
    # always spend the crypt() time, so an unknown user is not faster to reject
    my $hash = $rec ? $rec->{hash} : '$6$rounds=' . $s->{rounds} . '$csf2nouser$x';
    my $pw_ok = $s->check_password($pw // '', $hash);
    unless ($rec && $pw_ok && $rec->{totp} && $s->check_totp($user, $rec->{totp}, $code)) {
        $s->record_failure($ip);
        return (0, 'invalid');
    }
    $s->clear_failures($ip);
    return (1, 'ok');
}

###############################################################################
# sessions
sub create_session {
    my ($s, $user) = @_;
    my $dir = $s->_sdir; mkdir $dir, 0700 unless -d $dir;
    my $token = random_hex(32);
    my $csrf  = random_hex(16);
    my $now = $s->_now;
    my $f = "$dir/s-" . sha256_hex($token);
    sysopen(my $fh, $f, O_WRONLY | O_CREAT | O_EXCL, 0600) or return undef;
    print {$fh} join("\t", $user, $now, $now, $csrf) . "\n";
    close $fh;
    return { token => $token, csrf => $csrf, user => $user };
}

# check_session($token) -> { user, csrf } | undef   (also refreshes last-seen)
sub check_session {
    my ($s, $token) = @_;
    return undef unless defined $token && $token =~ /^[0-9a-f]{64}$/;
    my $f = $s->_sdir . '/s-' . sha256_hex($token);
    open my $fh, '<', $f or return undef;
    my $l = <$fh>; close $fh;
    chomp $l if defined $l;
    my ($user, $created, $last, $csrf) = split /\t/, ($l // '');
    my $now = $s->_now;
    if (!$user || $now - $created > $MAX_SECONDS || $now - $last > $IDLE_SECONDS
        || !$s->load_users->{$user}) {
        unlink $f; return undef;
    }
    if (open my $w, '>', $f) { print {$w} join("\t", $user, $created, $now, $csrf) . "\n"; close $w }
    return { user => $user, csrf => $csrf };
}

sub destroy_session {
    my ($s, $token) = @_;
    return unless defined $token && $token =~ /^[0-9a-f]{64}$/;
    unlink $s->_sdir . '/s-' . sha256_hex($token);
}

sub revoke_user_sessions {
    my ($s, $user) = @_;
    for my $f (glob($s->_sdir . '/s-*')) {
        open my $fh, '<', $f or next; my $l = <$fh>; close $fh;
        unlink $f if defined $l && (split /\t/, $l)[0] eq $user;
    }
}

# purge_sessions() - drop expired session files (called opportunistically)
sub purge_sessions {
    my ($s) = @_;
    my $now = $s->_now;
    for my $f (glob($s->_sdir . '/s-*')) {
        my $m = (stat $f)[9] // 0;
        unlink $f if $now - $m > $MAX_SECONDS;
    }
}

###############################################################################
# per-IP failure throttling: $var/ui-sessions/fail-<ip>  "count first_epoch"
sub _failfile {
    my ($s, $ip) = @_;
    my $k = $ip // 'unknown';
    if ($k ne 'global') { $k =~ s/[^0-9A-Fa-f.:]//g; $k =~ s/:/_/g }
    my $dir = $s->_sdir; mkdir $dir, 0700 unless -d $dir;
    return "$dir/fail-$k";
}
sub _failread {
    my ($s, $ip) = @_;
    open my $fh, '<', $s->_failfile($ip) or return (0, 0);
    my ($c, $t) = split ' ', (<$fh> // ''); close $fh;
    return ($c // 0, $t // 0);
}
sub is_locked {
    my ($s, $ip) = @_;
    my $now = $s->_now;
    my ($gc, $gt) = $s->_failread('global');
    return 1 if $now - $gt <= $FAIL_WINDOW && $gc >= $FAIL_GLOBAL;
    my ($c, $t) = $s->_failread($ip);
    return 0 if $now - $t > $FAIL_WINDOW;
    return $c >= $FAIL_LIMIT ? 1 : 0;
}
sub record_failure {
    my ($s, $ip) = @_;
    my $now = $s->_now;
    my $mine;
    for my $k ($ip, 'global') {
        my ($c, $t) = $s->_failread($k);
        ($c, $t) = (0, $now) if $now - $t > $FAIL_WINDOW;
        $c++;
        if (open my $fh, '>', $s->_failfile($k)) { print {$fh} "$c $t\n"; close $fh }
        $mine //= $c;
    }
    return $mine;
}
sub clear_failures { my ($s, $ip) = @_; unlink $s->_failfile($ip) }

1;
