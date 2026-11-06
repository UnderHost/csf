package CSF2::LFD;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::LFD - Login Failure Daemon 2.0.
#
# Event-driven pipeline: raw log line -> CSF2::Detect (normalised event) ->
# CSF2::Risk (correlation + score) -> CSF2::Engine (nftables set update). The
# core, process_line(), is a pure function of its inputs so it is fully
# unit-tested; the run loop only adds incremental log tailing and cursors.
#
# Trusted IPs (allow list + csf.ignore + server addresses) are never blocked.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
# LFD concept derives from ConfigServer Security & Firewall (GPLv3).
###############################################################################

use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);
use CSF2::IP qw(normalize ip_in_any);
use CSF2::Detect;
use CSF2::Risk;

sub new {
    my ($class, %a) = @_;
    my $self = {
        engine => $a{engine},
        detect => $a{detect} || CSF2::Detect->new,
        risk   => $a{risk}   || CSF2::Risk->new,
        state  => $a{state},                 # CSF2::State (for allow list)
        ignore => $a{ignore} || [],          # extra never-block IPs/CIDRs
        server_ips => $a{server_ips} || [],  # this host's own addresses
        logfiles => $a{logfiles} || [],      # [ path, ... ]
        var    => $a{var} || '/var/lib/csf',
        interval => $a{interval} || 5,
        journal  => $a{journal} || 0,        # also read auth/mail entries from journald
        journalctl => $a{journalctl} || '/usr/bin/journalctl',
        cursors => {},
    };
    return bless $self, $class;
}

###############################################################################
# journal_wanted(%opt) -> 1|0  - LF_JOURNAL "auto" means: journalctl exists and
# there is no syslog auth file (Debian 12+, minimal EL10), so SSH failures are
# only in the journal. "1" forces it on, "0" off.
sub journal_wanted {
    my ($class, %o) = @_;
    my $mode = defined $o{mode} ? lc $o{mode} : 'auto';
    my $jc   = $o{journalctl} || '/usr/bin/journalctl';
    my $root = $o{root} // '';
    return 0 if $mode eq '0' || $mode eq 'off';
    return 0 unless -x "$root$jc";
    return 1 if $mode eq '1' || $mode eq 'on';
    return (-e "$root/var/log/auth.log" || -e "$root/var/log/secure") ? 0 : 1;
}

###############################################################################
# journal_new() -> @new_lines  (auth, authpriv, mail and ftp facilities since
# the saved cursor, in classic syslog format so CSF2::Detect applies as-is)
sub journal_new {
    my ($self) = @_;
    return () unless $self->{journal};
    my @cmd = ($self->{journalctl}, '--no-pager', '-q', '-o', 'short', '--show-cursor',
               map({ "SYSLOG_FACILITY=$_" } 2, 4, 10, 11));
    my $cur = $self->{cursors}{journal};
    push @cmd, defined $cur && length $cur ? "--after-cursor=$cur" : ('--since', '@' . (time - 60));
    open(my $fh, '-|', @cmd) or return ();
    my @lines;
    while (my $l = <$fh>) {
        chomp $l;
        if ($l =~ /^-- cursor: (\S+)/) { $self->{cursors}{journal} = $1; next }
        push @lines, $l;
    }
    close $fh;
    return @lines;
}

###############################################################################
# is_ignored($ip) -> reason string | undef
sub is_ignored {
    my ($self, $ip) = @_;
    my $c = normalize($ip) // return undef;
    return 'server address' if ip_in_any($c, $self->{server_ips});
    return 'csf.ignore'     if ip_in_any($c, $self->{ignore});
    if ($self->{state}) {
        my @allow = map { $_->{canonical} } @{ $self->{state}->load_list('allow') };
        return 'allow list' if ip_in_any($c, \@allow);
    }
    return undef;
}

###############################################################################
# process_line($line, $now?) -> list of action hashrefs
#   { ip, action('monitor'|'temp'|'perm'|'ignored'), score, level, service,
#     timeout?, reason? }
sub process_line {
    my ($self, $line, $now) = @_;
    $now //= time;
    my @actions;
    for my $ev ($self->{detect}->scan($line)) {
        my $ip = $ev->{source_ip};
        if (my $why = $self->is_ignored($ip)) {
            push @actions, { ip=>$ip, action=>'ignored', reason=>$why, service=>$ev->{service} };
            next;
        }
        $self->{risk}->add_event($ip, $ev->{severity}, $now);
        my $eval = $self->{risk}->evaluate($ip, $now);
        my $comment = sprintf('LFD: %s %s (score %d)', $ev->{service}, $ev->{event}, int($eval->{score}));

        if ($eval->{block}) {
            my $timeout = $self->{risk}->record_block($ip, $now);
            if ($timeout == 0) {
                $self->{engine}->deny($ip, $comment) if $self->{engine};
                push @actions, { ip=>$ip, action=>'perm', score=>$eval->{score},
                                 level=>$eval->{level}, service=>$ev->{service}, reason=>$comment };
            } else {
                $self->{engine}->tempdeny($ip, $timeout, comment=>$comment) if $self->{engine};
                push @actions, { ip=>$ip, action=>'temp', timeout=>$timeout, score=>$eval->{score},
                                 level=>$eval->{level}, service=>$ev->{service}, reason=>$comment };
            }
        } else {
            push @actions, { ip=>$ip, action=>'monitor', score=>$eval->{score},
                             level=>$eval->{level}, service=>$ev->{service} };
        }
    }
    return @actions;
}

###############################################################################
# tail_new($file) -> @new_lines   (incremental; resets cursor on rotation)
sub tail_new {
    my ($self, $file) = @_;
    return () unless -e $file;
    my $size = (stat $file)[7];
    my $pos  = $self->{cursors}{$file} || 0;
    if ($size < $pos) { $pos = 0 }             # log rotated/truncated
    return () if $size == $pos;
    sysopen(my $fh, $file, O_RDONLY) or return ();
    seek($fh, $pos, 0);
    my @lines = <$fh>;
    $self->{cursors}{$file} = tell($fh);
    close $fh;
    chomp @lines;
    return @lines;
}

###############################################################################
# tick($now?) -> @actions   (one pass over all watched logfiles)
sub tick {
    my ($self, $now) = @_;
    $now //= time;
    my @actions;
    for my $file (@{ $self->{logfiles} }) {
        for my $line ($self->tail_new($file)) {
            push @actions, $self->process_line($line, $now);
        }
    }
    push @actions, $self->process_line($_, $now) for $self->journal_new;
    return @actions;
}

###############################################################################
# Cursor persistence (survive restarts without re-scanning whole logs)
sub _cursor_file { my $s = shift; return "$s->{var}/csf.logcursors" }

sub save_cursors {
    my ($self) = @_;
    sysopen(my $fh, $self->_cursor_file, O_WRONLY | O_CREAT | O_TRUNC) or return 0;
    flock($fh, LOCK_EX);
    for my $f (sort keys %{ $self->{cursors} }) { print {$fh} "$f|$self->{cursors}{$f}\n" }
    close $fh;
    return 1;
}

sub load_cursors {
    my ($self) = @_;
    my $file = $self->_cursor_file;
    return 0 unless -e $file;
    sysopen(my $fh, $file, O_RDONLY) or return 0;
    while (my $l = <$fh>) { chomp $l; my ($f,$p) = split /\|/, $l; $self->{cursors}{$f} = $p if defined $p }
    close $fh;
    return 1;
}

###############################################################################
# run() - the daemon loop. Kept thin: real work is in tick()/process_line().
# Detection latency is bounded by 'interval'; a journald/inotify collector can
# replace polling later without touching the pipeline above.
sub run {
    my ($self, %opts) = @_;
    my $risk_db = "$self->{var}/csf.risk";
    $self->load_cursors;
    $self->{risk}->load($risk_db);
    my $max = $opts{max_ticks};    # for bounded runs / testing
    my $n = 0;
    while (1) {
        my @actions = $self->tick();
        for my $a (@actions) {
            next if $a->{action} eq 'monitor' || $a->{action} eq 'ignored';
            _log($self, "blocked $a->{ip} ($a->{action}) - $a->{reason}");
        }
        $self->save_cursors;
        $self->{risk}->save($risk_db);
        $self->{risk}->prune();
        last if defined $max && ++$n >= $max;
        sleep $self->{interval};
    }
    return;
}

sub _log {
    my ($self, $msg) = @_;
    my $f = "$self->{var}/lfd.log";
    if (sysopen(my $fh, $f, O_WRONLY | O_APPEND | O_CREAT)) {
        print {$fh} scalar(localtime) . " lfd: $msg\n";
        close $fh;
    }
    return;
}

1;
