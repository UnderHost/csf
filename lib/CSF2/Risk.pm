package CSF2::Risk;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Risk - security-event correlation, IP risk scoring and progressive
# enforcement.
#
# Instead of counting one log source at a time, events from every service roll
# up into a single decaying risk score per IP. Crossing a threshold triggers an
# action; repeat offenders escalate through progressively longer blocks. Every
# number here is configurable and documented - none are hard-coded magic.
#
# Time is injectable ($now) so the decay/escalation logic is fully unit-tested.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);
use CSF2::IP qw(normalize);

# Documented defaults. Override any via new(%opts).
our %DEFAULTS = (
    HALFLIFE      => 3600,     # seconds for a score to halve (reputation decay)
    T_MONITOR     => 30,       # >= : watch
    T_THROTTLE    => 50,       # >= : rate-limit candidate
    T_SHORT_BLOCK => 70,       # >= : temporary block
    T_LONG_BLOCK  => 90,       # >= : extended block
    T_PERM        => 100,      # >= : high-confidence hostile
    # Progressive block durations by offence number (seconds). 0 => permanent.
    ESCALATION    => [300, 1800, 21600, 86400],   # 5m, 30m, 6h, 24h
    PERM_AFTER    => 5,        # offence number at which blocks become permanent
    OFFENSE_TTL   => 604800,   # idle seconds before offence count is forgiven (7d)
);

sub new {
    my ($class, %opts) = @_;
    my $self = { %DEFAULTS, %opts, ip => {} };
    return bless $self, $class;
}

# _entry($ip) -> hashref { score, seen, offenses, last_block }
sub _entry {
    my ($self, $ip) = @_;
    return $self->{ip}{$ip} ||= { score => 0, seen => 0, offenses => 0, last_block => 0 };
}

# _decay($score, $elapsed) -> decayed score (half-life)
sub _decay {
    my ($self, $score, $elapsed) = @_;
    return $score if $elapsed <= 0 || $score <= 0;
    return $score * (0.5 ** ($elapsed / $self->{HALFLIFE}));
}

###############################################################################
# add_event($ip, $severity, $now?) -> current score
sub add_event {
    my ($self, $ip, $severity, $now) = @_;
    $ip = normalize($ip) // $ip;
    $now //= time;
    my $e = $self->_entry($ip);
    # decay the existing score up to now, then add this event.
    $e->{score} = $self->_decay($e->{score}, $now - $e->{seen});
    $e->{score} += ($severity || 0);
    $e->{seen}   = $now;
    return $e->{score};
}

# score($ip, $now?) -> decayed score right now (no mutation of stored 'seen')
sub score {
    my ($self, $ip, $now) = @_;
    $ip = normalize($ip) // $ip;
    $now //= time;
    my $e = $self->{ip}{$ip} or return 0;
    return $self->_decay($e->{score}, $now - $e->{seen});
}

# level($score) -> 'clear'|'monitor'|'throttle'|'short'|'long'|'perm'
sub level {
    my ($self, $s) = @_;
    return 'perm'     if $s >= $self->{T_PERM};
    return 'long'     if $s >= $self->{T_LONG_BLOCK};
    return 'short'    if $s >= $self->{T_SHORT_BLOCK};
    return 'throttle' if $s >= $self->{T_THROTTLE};
    return 'monitor'  if $s >= $self->{T_MONITOR};
    return 'clear';
}

# evaluate($ip, $now?) -> { score, level, block(bool) }
sub evaluate {
    my ($self, $ip, $now) = @_;
    my $s = $self->score($ip, $now);
    my $lvl = $self->level($s);
    my $block = ($lvl eq 'short' || $lvl eq 'long' || $lvl eq 'perm') ? 1 : 0;
    return { score => $s, level => $lvl, block => $block };
}

###############################################################################
# next_timeout($ip, $now?) -> seconds for the NEXT block (0 => permanent)
# Progressive: forgives stale offences first, then indexes ESCALATION.
sub next_timeout {
    my ($self, $ip, $now) = @_;
    $ip = normalize($ip) // $ip;
    $now //= time;
    my $e = $self->_entry($ip);
    # forgive offences if the IP has been quiet longer than OFFENSE_TTL
    if ($e->{last_block} && ($now - $e->{last_block}) > $self->{OFFENSE_TTL}) {
        $e->{offenses} = 0;
    }
    my $n = $e->{offenses};   # 0-based index into ESCALATION for the next block
    return 0 if $n >= $self->{PERM_AFTER} - 1 && $self->{PERM_AFTER} > 0
                && $n >= scalar(@{ $self->{ESCALATION} });
    my $esc = $self->{ESCALATION};
    return 0 if $n >= @$esc;         # beyond the ladder => permanent
    return $esc->[$n];
}

# record_block($ip, $now?) -> the timeout that was applied (after incrementing)
sub record_block {
    my ($self, $ip, $now) = @_;
    $ip = normalize($ip) // $ip;
    $now //= time;
    my $timeout = $self->next_timeout($ip, $now);
    my $e = $self->_entry($ip);
    $e->{offenses}++;
    $e->{last_block} = $now;
    return $timeout;
}

###############################################################################
# Persistence (pipe format: ip|score|seen|offenses|last_block)
sub save {
    my ($self, $file) = @_;
    sysopen(my $fh, $file, O_WRONLY | O_CREAT | O_TRUNC) or return 0;
    flock($fh, LOCK_EX);
    for my $ip (sort keys %{ $self->{ip} }) {
        my $e = $self->{ip}{$ip};
        print {$fh} join('|', $ip, sprintf('%.3f',$e->{score}), $e->{seen}, $e->{offenses}, $e->{last_block}) . "\n";
    }
    close $fh;
    return 1;
}

sub load {
    my ($self, $file) = @_;
    return 0 unless -e $file;
    sysopen(my $fh, $file, O_RDONLY) or return 0;
    flock($fh, LOCK_SH);
    while (my $l = <$fh>) {
        chomp $l;
        next unless $l =~ /\S/;
        my ($ip, $score, $seen, $off, $lb) = split /\|/, $l;
        $self->{ip}{$ip} = { score=>($score||0), seen=>($seen||0), offenses=>($off||0), last_block=>($lb||0) };
    }
    close $fh;
    return 1;
}

# prune($now?) - drop entries whose decayed score is ~0 and no recent offences.
sub prune {
    my ($self, $now) = @_;
    $now //= time;
    for my $ip (keys %{ $self->{ip} }) {
        my $s = $self->score($ip, $now);
        my $e = $self->{ip}{$ip};
        if ($s < 1 && (!$e->{last_block} || ($now - $e->{last_block}) > $self->{OFFENSE_TTL})) {
            delete $self->{ip}{$ip};
        }
    }
    return;
}

1;
