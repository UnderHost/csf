package CSF2::Nft;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Nft - low-level nftables driver.
#
# SECURITY: every nft invocation is executed in LIST FORM (no shell), so no
# argument is ever interpreted by /bin/sh. Callers still pass only validated,
# canonical addresses (see CSF2::IP), but even if they did not, there is no
# shell metacharacter surface here.
#
# Incremental operations (add/delete one element) never rebuild the ruleset.
# Full (re)generation is applied atomically via `nft -f` after `nft -c -f`
# validation, giving generate -> validate -> apply -> verify -> rollback.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use IPC::Open3;
use Symbol qw(gensym);
use CSF2::Ruleset;

our $TABLE_FAMILY = 'inet';
our $TABLE_NAME   = 'csf';

###############################################################################
# new(%opts)
#   nft      => path to nft binary (default: autodetect)
#   dry_run  => 1 to record commands instead of executing (testing / preview)
# Backend selection:
#   'nft'     - drive the nft(8) binary (portable default; always available).
#   'netlink' - manage via libnftables directly (optional, set up by installer
#               when a libnftables FFI/XS helper is present). Falls back to
#               'nft' automatically if the helper is not loadable, so callers
#               never have to branch. Both apply the SAME atomic transactions.
our $HAVE_NETLINK = 0;   # flipped on when a netlink helper is wired in

sub new {
    my ($class, %opts) = @_;
    my $backend = $opts{backend} || 'nft';
    $backend = 'nft' if $backend eq 'netlink' && !$HAVE_NETLINK;
    my $self = {
        nft     => $opts{nft}     || _find_nft(),
        dry_run => $opts{dry_run} ? 1 : 0,
        backend => $backend,
        log     => [],           # recorded argv lists (dry-run + audit)
    };
    return bless $self, $class;
}

sub backend { return $_[0]->{backend} }

sub _find_nft {
    for my $p (qw(/usr/sbin/nft /sbin/nft /usr/bin/nft)) {
        return $p if -x $p;
    }
    return 'nft';   # rely on PATH as a last resort
}

sub available { my $self = shift; return ($self->{nft} && -x $self->{nft}) ? 1 : 0 }
sub log       { my $self = shift; return $self->{log} }

###############################################################################
# _run(@argv) -> (exit_code, output)
# List-form exec; captures merged stdout+stderr. In dry-run, records and
# returns success without touching the system.
sub _run {
    my ($self, @argv) = @_;
    push @{ $self->{log} }, [@argv];
    return (0, q{}) if $self->{dry_run};

    my $err = gensym();
    my ($wtr, $rdr);
    my $pid = eval { open3($wtr, $rdr, $err, @argv) };
    if ($@) { return (255, "exec failed: $@") }
    close $wtr;   # no stdin for these commands
    my $out  = do { local $/; readline($rdr) };
    my $eout = do { local $/; readline($err) };
    waitpid($pid, 0);
    my $code = $? >> 8;
    return ($code, (($out // q{}) . ($eout // q{})));
}

# _run_stdin(\@argv, $stdin) -> (code, output)  - feed a ruleset via stdin.
sub _run_stdin {
    my ($self, $argv, $stdin) = @_;
    push @{ $self->{log} }, [@$argv, '<<stdin>>'];
    return (0, q{}) if $self->{dry_run};

    # Feed nft through a temp FILE, not a stdin pipe. A large script - a Threat
    # Intelligence set can carry tens of thousands of elements, far exceeding the
    # ~64KB OS pipe buffer - would otherwise DEADLOCK: this process blocks
    # writing all of stdin while nft blocks writing output that nothing is
    # draining yet, so both hang at 0% CPU forever (and an hourly cron then
    # stacks a new hung pair every hour). `nft -f <file>` reads the whole script
    # from a file with no pipe, so it cannot deadlock.
    my @cmd = @$argv;
    my $has_dash = 0;
    for my $a (@cmd) { if (defined $a && $a eq '-') { $has_dash = 1; last } }
    return $self->_run(@cmd) unless $has_dash;   # nothing to feed

    my ($fh, $path);
    eval {
        require File::Temp;
        ($fh, $path) = File::Temp::tempfile('csf-nftXXXXXX', TMPDIR => 1, UNLINK => 0);
        1;
    } or return (255, "cannot create temp file for nft: $@");
    binmode $fh;
    print {$fh} $stdin;
    close $fh;
    for my $a (@cmd) { $a = $path if defined $a && $a eq '-' }   # '-' -> file path
    my ($code, $out) = $self->_run(@cmd);
    unlink $path;
    return ($code, $out);
}

###############################################################################
# Set element operations (incremental - no rebuild)
#
# add_element($set, @elements)   e.g. add_element('csf_deny4', '1.2.3.4')
# add_timeout($set, $ip, $secs)  e.g. add_timeout('csf_temp4','1.2.3.4',3600)
# del_element($set, @elements)
sub add_element {
    my ($self, $set, @elems) = @_;
    return (0, 'no elements') unless @elems;
    my $spec = '{ ' . join(', ', @elems) . ' }';
    my ($c, $o) = $self->_run($self->{nft}, 'add', 'element',
        $TABLE_FAMILY, $TABLE_NAME, $set, $spec);
    return ((!$c) ? 1 : 0, $o);
}

sub add_timeout {
    my ($self, $set, $ip, $secs) = @_;
    $secs ||= 3600;
    my $spec = "{ $ip timeout ${secs}s }";
    my ($c, $o) = $self->_run($self->{nft}, 'add', 'element',
        $TABLE_FAMILY, $TABLE_NAME, $set, $spec);
    return ((!$c) ? 1 : 0, $o);
}

sub del_element {
    my ($self, $set, @elems) = @_;
    return (0, 'no elements') unless @elems;
    my $spec = '{ ' . join(', ', @elems) . ' }';
    my ($c, $o) = $self->_run($self->{nft}, 'delete', 'element',
        $TABLE_FAMILY, $TABLE_NAME, $set, $spec);
    return ((!$c) ? 1 : 0, $o);
}

###############################################################################
# apply_batch(\@ops) -> (ok, output)
# Apply many element operations as ONE atomic nftables transaction instead of
# forking nft per IP. Essential for loading large reputation/abuse feeds
# (10k-100k entries) without per-element round-trips.
#   @ops = ( { op=>'add'|'delete', set=>'csf_deny4', elem=>'1.2.3.4' },
#            { op=>'add', set=>'csf_temp4', elem=>'5.6.7.8 timeout 3600s' }, ... )
sub apply_batch {
    my ($self, $ops) = @_;
    return (1, 'empty') unless $ops && @$ops;
    my @lines;
    for my $o (@$ops) {
        my $op = ($o->{op} && $o->{op} eq 'delete') ? 'delete' : 'add';
        push @lines, "$op element $TABLE_FAMILY $TABLE_NAME $o->{set} { $o->{elem} }";
    }
    my $script = join("\n", @lines) . "\n";
    push @{ $self->{log} }, ['<<batch>>', scalar(@$ops) . ' ops'];
    return (1, 'batched') if $self->{dry_run};
    my ($code, $out) = $self->_run_stdin([$self->{nft}, '-f', '-'], $script);
    return ((!$code) ? 1 : 0, $out);
}

# load_set($set, \@elements) -> (ok, output)
# Atomically REPLACE a set's contents: flush + add in one transaction. Built for
# large reputation feeds (tens of thousands of CIDRs) loaded into TI sets.
sub load_set {
    my ($self, $set, $elems) = @_;
    my $script = "flush set $TABLE_FAMILY $TABLE_NAME $set\n";
    if ($elems && @$elems) {
        $script .= "add element $TABLE_FAMILY $TABLE_NAME $set { " . join(', ', @$elems) . " }\n";
    }
    push @{ $self->{log} }, ['<<load_set>>', $set, scalar(@{ $elems || [] }) . ' elems'];
    return (1, 'loaded') if $self->{dry_run};
    my ($code, $out) = $self->_run_stdin([$self->{nft}, '-f', '-'], $script);
    return ((!$code) ? 1 : 0, $out);
}

# list_json() -> (ok, text)  structured output via libnftables (nft -j).
# Callers with a JSON parser get a machine-readable view; the same data the
# netlink backend would return natively.
sub list_json {
    my ($self) = @_;
    my ($code, $out) = $self->_run($self->{nft}, '-j', 'list', 'table', $TABLE_FAMILY, $TABLE_NAME);
    return ((!$code) ? 1 : 0, $out);
}

###############################################################################
# Ruleset lifecycle
#
# validate($script) -> (ok, output)  : nft -c -f - (syntax check, no apply)
# apply($script)     -> (ok, output)  : nft -f -    (atomic transaction)
# list_ruleset()     -> (ok, text)    : nft list ruleset
# save($file)        -> (ok, output)  : persist current ruleset for rollback
# table_exists()     -> bool
# delete_table()     -> (ok, output)
sub validate {
    my ($self, $script) = @_;
    my ($code, $out) = $self->_run_stdin([$self->{nft}, '-c', '-f', '-'], $script);
    return ((!$code) ? 1 : 0, $out);
}

sub apply {
    my ($self, $script) = @_;
    my ($code, $out) = $self->_run_stdin([$self->{nft}, '-f', '-'], $script);
    return ((!$code) ? 1 : 0, $out);
}

sub list_ruleset {
    my ($self) = @_;
    my ($code, $out) = $self->_run($self->{nft}, 'list', 'ruleset');
    return ((!$code) ? 1 : 0, $out);
}

sub list_table {
    my ($self) = @_;
    my ($code, $out) = $self->_run($self->{nft}, 'list', 'table', $TABLE_FAMILY, $TABLE_NAME);
    return ((!$code) ? 1 : 0, $out);
}

sub table_exists {
    my ($self) = @_;
    return 1 if $self->{dry_run};
    my ($ok) = $self->list_table();
    return $ok;
}

sub delete_table {
    my ($self) = @_;
    return $self->_run($self->{nft}, 'delete', 'table', $TABLE_FAMILY, $TABLE_NAME);
}

# save_or_capture() -> (ok, rollback_script)
# Captures the current "table inet csf" as a self-contained script that, when
# applied with `nft -f`, atomically restores it (delete-then-recreate). Empty
# string means the table did not exist (nothing to roll back to).
sub save_or_capture {
    my ($self) = @_;
    return (1, q{}) if $self->{dry_run};
    my ($ok, $text) = $self->list_table();
    return (0, q{}) unless $ok;
    return (1, q{}) if !defined $text || $text !~ /\S/;
    my $rollback = "table $TABLE_FAMILY $TABLE_NAME {}\n"
                 . "delete table $TABLE_FAMILY $TABLE_NAME\n\n"
                 . $text;
    return (1, $rollback);
}

sub save {
    my ($self, $file) = @_;
    my ($ok, $text) = $self->list_ruleset();
    return (0, $text) unless $ok;
    return (1, $text) if $self->{dry_run};
    open my $fh, '>', $file or return (0, "open $file: $!");
    print {$fh} $text;
    close $fh;
    return (1, $file);
}

1;
