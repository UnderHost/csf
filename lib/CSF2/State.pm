package CSF2::State;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::State - persistent allow/deny/temp state.
#
# On-disk format stays compatible with legacy CSF: csf.allow and csf.deny are
# line lists of "IP # comment". Every address is canonicalised through CSF2::IP
# on the way in, so a host can never be stored twice under two spellings.
#
# Temporary bans are recorded here for the UI / reload repopulation, but the
# kernel (nftables set timeouts) is the source of truth for expiry.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);
use CSF2::IP qw(parse);

###############################################################################
# new(%opts)
#   etc => config dir  (default /etc/csf)
#   var => runtime dir (default /var/lib/csf)
sub new {
    my ($class, %opts) = @_;
    my $self = {
        etc => $opts{etc} || '/etc/csf',
        var => $opts{var} || '/var/lib/csf',
    };
    return bless $self, $class;
}

sub _path      { my ($s,$f) = @_; return "$s->{etc}/$f" }
sub _var_path  { my ($s,$f) = @_; return "$s->{var}/$f" }

###############################################################################
# _read_lines($file) -> @lines (chomped); missing file => empty list
sub _read_lines {
    my ($self, $file) = @_;
    return () unless -e $file;
    sysopen(my $fh, $file, O_RDONLY) or return ();
    flock($fh, LOCK_SH);
    my @l = <$fh>;
    close $fh;
    chomp @l;
    return @l;
}

###############################################################################
# load_list($name) -> arrayref of { canonical, comment, type, kind, set }
# $name is 'allow' or 'deny' (=> csf.allow / csf.deny)
sub load_list {
    my ($self, $name) = @_;
    my $file = $self->_path("csf.$name");
    my @rows;
    my %seen;
    for my $line ($self->_read_lines($file)) {
        next if $line =~ /^\s*#/ || $line =~ /^\s*$/;
        my ($tok, $comment) = split /\s*#\s*/, $line, 2;
        $tok =~ s/^\s+|\s+$//g;
        my $p = parse($tok);
        next unless $p;                       # skip malformed silently in view
        next if $seen{$p->{canonical}}++;     # dedup
        push @rows, {
            canonical => $p->{canonical}, comment => ($comment // q{}),
            type => $p->{type}, kind => $p->{kind}, set => $p->{set},
        };
    }
    return \@rows;
}

###############################################################################
# in_list($name, $ip) -> canonical string if present, else undef
sub in_list {
    my ($self, $name, $ip) = @_;
    my $p = parse($ip) or return undef;
    for my $r (@{ $self->load_list($name) }) {
        return $r->{canonical} if $r->{canonical} eq $p->{canonical};
    }
    return undef;
}

###############################################################################
# add_to_list($name, $ip, $comment) -> (ok, message)
sub add_to_list {
    my ($self, $name, $ip, $comment) = @_;
    my $p = parse($ip) or return (0, "invalid address: $ip");
    return (0, "$p->{canonical} already in csf.$name")
        if $self->in_list($name, $p->{canonical});
    my $file = $self->_path("csf.$name");
    sysopen(my $fh, $file, O_WRONLY | O_APPEND | O_CREAT) or return (0, "open $file: $!");
    flock($fh, LOCK_EX);
    my $line = $p->{canonical};
    $line .= " # $comment" if defined $comment && $comment ne q{};
    print {$fh} "$line\n";
    close $fh;
    return (1, "added $p->{canonical} to csf.$name");
}

###############################################################################
# remove_from_list($name, $ip) -> (ok, message)
sub remove_from_list {
    my ($self, $name, $ip) = @_;
    my $p = parse($ip) or return (0, "invalid address: $ip");
    my $file = $self->_path("csf.$name");
    return (0, "csf.$name not found") unless -e $file;
    my @lines = $self->_read_lines($file);
    my @keep;
    my $removed = 0;
    for my $line (@lines) {
        if ($line =~ /^\s*#/ || $line =~ /^\s*$/) { push @keep, $line; next }
        my ($tok) = split /\s*#\s*/, $line, 2;
        $tok =~ s/^\s+|\s+$//g;
        my $q = parse($tok);
        if ($q && $q->{canonical} eq $p->{canonical}) { $removed++; next }
        push @keep, $line;
    }
    return (0, "$p->{canonical} not in csf.$name") unless $removed;
    _atomic_write($file, join("\n", @keep) . (@keep ? "\n" : q{}));
    return (1, "removed $p->{canonical} from csf.$name");
}

###############################################################################
# Temporary bans
# temp record: epoch|ip|family|kind|timeout|port|comment
sub _temp_file { my $s = shift; return $s->_var_path('csf.tempban') }

sub temp_add {
    my ($self, %a) = @_;
    my $p = parse($a{ip}) or return (0, "invalid address: $a{ip}");
    my $kind    = ($a{kind} && $a{kind} eq 'allow') ? 'allow' : 'deny';
    my $timeout = $a{timeout} || 3600;
    my $port    = defined $a{port} ? $a{port} : q{};
    my $comment = defined $a{comment} ? $a{comment} : q{};
    $comment =~ s/[|\n]/ /g;
    # One entry per address/kind/port: a repeat (LFD escalation) replaces the
    # old line and keeps whichever expiry is later. Returns the effective
    # timeout so the caller can set the same one in the kernel set.
    my $file = $self->_temp_file();
    sysopen(my $fh, $file, O_RDWR | O_CREAT) or return (0, "open $file: $!");
    flock($fh, LOCK_EX);
    my $now = time;
    my $until = $now + $timeout;
    my @keep;
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*$/;
        my ($epoch, $ip, undef, $k, $to, $pt) = split /\|/, $line, 7;
        if (defined $ip && $ip eq $p->{canonical} && ($k // '') eq $kind && ($pt // '') eq $port) {
            my $exp = ($epoch || 0) + ($to || 0);
            $until = $exp if $exp > $until;
            next;
        }
        push @keep, $line;
    }
    $timeout = $until - $now;
    seek($fh, 0, 0); truncate($fh, 0);
    print {$fh} "$_\n" for @keep;
    print {$fh} join('|', $now, $p->{canonical}, $p->{type}, $kind, $timeout, $port, $comment) . "\n";
    close $fh;
    return (1, "temp $kind $p->{canonical} for ${timeout}s", $timeout);
}

# temp_load(%opts) -> arrayref of records; purges expired entries from the view
# (and rewrites the file) unless keep_expired => 1.
sub temp_load {
    my ($self, %opts) = @_;
    my $file = $self->_temp_file();
    my @rows;
    my @keep;
    my $now = time;
    for my $line ($self->_read_lines($file)) {
        next if $line =~ /^\s*$/;
        my ($epoch, $ip, $fam, $kind, $timeout, $port, $comment) = split /\|/, $line, 7;
        next unless defined $ip;
        my $expires = $epoch + ($timeout || 0);
        my $rec = {
            epoch => $epoch, ip => $ip, family => $fam, kind => $kind,
            timeout => $timeout, port => ($port // q{}), comment => ($comment // q{}),
            expires => $expires, expired => ($now >= $expires ? 1 : 0),
        };
        push @rows, $rec;
        push @keep, $line unless $rec->{expired};
    }
    if (!$opts{keep_expired} && @rows != @keep) {
        _atomic_write($file, join("\n", @keep) . (@keep ? "\n" : q{}));
    }
    return \@rows;
}

sub temp_remove {
    my ($self, $ip) = @_;
    my $p = parse($ip) or return (0, "invalid address: $ip");
    my $file = $self->_temp_file();
    return (0, 'no temp bans') unless -e $file;
    my @keep;
    my $removed = 0;
    for my $line ($self->_read_lines($file)) {
        next if $line =~ /^\s*$/;
        my (undef, $lip) = split /\|/, $line, 3;
        if (defined $lip && $lip eq $p->{canonical}) { $removed++; next }
        push @keep, $line;
    }
    return (0, "$p->{canonical} not temporarily blocked") unless $removed;
    _atomic_write($file, join("\n", @keep) . (@keep ? "\n" : q{}));
    return (1, "removed temp $p->{canonical}");
}

sub temp_flush {
    my ($self) = @_;
    _atomic_write($self->_temp_file(), q{});
    return (1, 'temp bans flushed');
}

###############################################################################
# state_for_ruleset() -> hashref consumed by CSF2::Ruleset::build
# Partitions everything into per-family sets and live temp entries.
sub state_for_ruleset {
    my ($self) = @_;
    my %st = (allow4=>[], allow6=>[], deny4=>[], deny6=>[], temp=>[]);
    for my $r (@{ $self->load_list('allow') }) {
        push @{ $st{"allow$r->{set}"} }, $r->{canonical};
    }
    for my $r (@{ $self->load_list('deny') }) {
        push @{ $st{"deny$r->{set}"} }, $r->{canonical};
    }
    for my $t (@{ $self->temp_load() }) {
        next if $t->{expired};
        my $remaining = $t->{expires} - time;
        $remaining = 1 if $remaining < 1;
        push @{ $st{temp} }, {
            ip => $t->{ip}, family => $t->{family}, kind => $t->{kind},
            timeout => $remaining,
        };
    }
    return \%st;
}

###############################################################################
# _atomic_write($file, $content) - write via temp + rename (never truncate live)
sub _atomic_write {
    my ($file, $content) = @_;
    my $tmp = "$file.tmp.$$";
    sysopen(my $fh, $tmp, O_WRONLY | O_CREAT | O_TRUNC) or return 0;
    flock($fh, LOCK_EX);
    print {$fh} $content;
    close $fh;
    rename($tmp, $file) or do { unlink $tmp; return 0 };
    return 1;
}

1;
