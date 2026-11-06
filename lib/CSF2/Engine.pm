package CSF2::Engine;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Engine - orchestrates State + Ruleset + Nft + Lockout.
#
# Two paths:
#   * Incremental ops (deny/allow/tempdeny/...) touch ONE nftables set element
#     and never rebuild the ruleset - O(1), the core performance guarantee.
#   * reload() does the full generate -> lockout guard -> validate -> apply ->
#     verify -> rollback cycle, atomically.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use CSF2::IP qw(parse);
use CSF2::Ruleset;
use CSF2::Lockout;

sub new {
    my ($class, %a) = @_;
    my $self = {
        config => $a{config},   # CSF2::Config object
        state  => $a{state},    # CSF2::State object
        nft    => $a{nft},      # CSF2::Nft object
        xdp    => $a{xdp},      # optional CSF2::XDP (fast-drop) - may be undef
    };
    return bless $self, $class;
}

sub _cfg { my $s = shift; my %c = $s->{config}->config; return \%c }

###############################################################################
# reload(%opts) -> \%result
#   force    => skip lockout blocks (still reported)
#   dry_run  => build+validate+guard only, never apply
# result: { ok, applied, guard, validated, error, script }
sub reload {
    my ($self, %opts) = @_;
    my $cfg   = $self->_cfg();
    my $state = $self->{state}->state_for_ruleset();

    # generate
    my $script = CSF2::Ruleset::build($cfg, $state);

    # lockout guard (only meaningful when enforcing with drop policy)
    my $guard = CSF2::Lockout::guard($cfg, $state, force => $opts{force});

    my %res = (ok => 0, applied => 0, guard => $guard, validated => 0,
               error => undef, script => $script);

    if (!$guard->{ok}) {
        $res{error} = "lockout guard refused apply: " . join('; ', @{ $guard->{blocks} });
        return \%res;
    }

    # validate candidate ruleset (nft -c)
    my ($vok, $vout) = $self->{nft}->validate($script);
    $res{validated} = $vok;
    if (!$vok) {
        $res{error} = "ruleset validation failed: $vout";
        return \%res;
    }

    if ($opts{dry_run}) { $res{ok} = 1; return \%res }

    # TESTING mode: generate + validate + guard, but do NOT apply (documented
    # behaviour). --force overrides so an admin can apply while still testing.
    if ($cfg->{TESTING} && !$opts{force}) {
        $res{ok} = 1;
        $res{testing} = 1;
        return \%res;
    }

    # snapshot for rollback
    my ($sok, $prev) = $self->{nft}->save_or_capture();

    # apply atomically
    my ($aok, $aout) = $self->{nft}->apply($script);
    if (!$aok) {
        $res{error} = "apply failed: $aout";
        # attempt rollback to previous snapshot
        if ($sok && defined $prev && $prev ne q{}) { $self->{nft}->apply($prev) }
        return \%res;
    }

    # verify the table landed
    if (!$self->{nft}->table_exists()) {
        $res{error} = "post-apply verification failed: table inet csf missing";
        if ($sok && defined $prev && $prev ne q{}) { $self->{nft}->apply($prev) }
        return \%res;
    }

    $res{ok} = 1; $res{applied} = 1;
    return \%res;
}

###############################################################################
# Incremental operations - one set element, no rebuild.

# _set_for($kind, $type) -> set name; kind in permanent/temp/allowtemp
sub _deny_set  { my ($self,$fam)=@_; return "csf_deny$fam" }
sub _allow_set { my ($self,$fam)=@_; return "csf_allow$fam" }
sub _temp_set  { my ($self,$fam)=@_; return "csf_temp$fam" }
sub _tallow_set{ my ($self,$fam)=@_; return "csf_tallow$fam" }

# deny($ip, $comment) -> (ok, message)
sub deny {
    my ($self, $ip, $comment) = @_;
    my $p = parse($ip) or return (0, "csf: [$ip] is not a valid IP or CIDR");
    if ($self->{state}->in_list('allow', $p->{canonical})) {
        return (0, "csf: $p->{canonical} is in the allow list; remove it first");
    }
    my ($ok, $msg) = $self->{state}->add_to_list('deny', $p->{canonical}, $comment);
    return ($ok, $msg) unless $ok;
    # push to kernel if the table is live
    if ($self->{nft}->table_exists()) {
        $self->{nft}->add_element($self->_deny_set($p->{set}), $p->{canonical});
    }
    # optional XDP fast-drop for single severe addresses (never CIDR)
    if ($self->{xdp} && $p->{kind} eq 'ip' && $self->{xdp}->available) {
        $self->{xdp}->drop_add($p->{canonical});
    }
    return (1, "csf: $p->{canonical} added to the deny list and blocked");
}

# undeny($ip) -> (ok, message)
sub undeny {
    my ($self, $ip) = @_;
    my $p = parse($ip) or return (0, "csf: [$ip] is not a valid IP or CIDR");
    my ($ok, $msg) = $self->{state}->remove_from_list('deny', $p->{canonical});
    if ($self->{nft}->table_exists()) {
        $self->{nft}->del_element($self->_deny_set($p->{set}), $p->{canonical});
    }
    if ($self->{xdp} && $p->{kind} eq 'ip' && $self->{xdp}->available) {
        $self->{xdp}->drop_del($p->{canonical});
    }
    return ($ok, $ok ? "csf: $p->{canonical} removed from the deny list" : $msg);
}

# allow($ip, $comment) -> (ok, message)
sub allow {
    my ($self, $ip, $comment) = @_;
    my $p = parse($ip) or return (0, "csf: [$ip] is not a valid IP or CIDR");
    my ($ok, $msg) = $self->{state}->add_to_list('allow', $p->{canonical}, $comment);
    return ($ok, $msg) unless $ok;
    if ($self->{nft}->table_exists()) {
        $self->{nft}->add_element($self->_allow_set($p->{set}), $p->{canonical});
        # also drop any live block on this IP
        $self->{nft}->del_element($self->_deny_set($p->{set}), $p->{canonical});
        $self->{nft}->del_element($self->_temp_set($p->{set}), $p->{canonical});
    }
    return (1, "csf: $p->{canonical} added to the allow list");
}

# unallow($ip) -> (ok, message)
sub unallow {
    my ($self, $ip) = @_;
    my $p = parse($ip) or return (0, "csf: [$ip] is not a valid IP or CIDR");
    my ($ok, $msg) = $self->{state}->remove_from_list('allow', $p->{canonical});
    if ($self->{nft}->table_exists()) {
        $self->{nft}->del_element($self->_allow_set($p->{set}), $p->{canonical});
    }
    return ($ok, $ok ? "csf: $p->{canonical} removed from the allow list" : $msg);
}

# tempdeny($ip, $timeout, %opts) -> (ok, message)
#   %opts: kind => 'deny'|'allow', comment, port
sub tempdeny {
    my ($self, $ip, $timeout, %opts) = @_;
    my $p = parse($ip) or return (0, "csf: [$ip] is not a valid IP or CIDR");
    $timeout ||= 3600;
    my $kind = ($opts{kind} && $opts{kind} eq 'allow') ? 'allow' : 'deny';
    my ($ok, $msg, $eff) = $self->{state}->temp_add(
        ip => $p->{canonical}, kind => $kind, timeout => $timeout,
        comment => $opts{comment}, port => $opts{port},
    );
    return ($ok, $msg) unless $ok;
    $timeout = $eff if $eff;
    if ($self->{nft}->table_exists()) {
        my $set = $kind eq 'allow' ? $self->_tallow_set($p->{set}) : $self->_temp_set($p->{set});
        # "add element" keeps an existing element's old timeout: replace it so
        # an escalated (longer) block really lasts longer in the kernel
        $self->{nft}->del_element($set, $p->{canonical});
        $self->{nft}->add_timeout($set, $p->{canonical}, $timeout);
    }
    my %past = (deny => 'denied', allow => 'allowed');
    return (1, "csf: $p->{canonical} temporarily $past{$kind} for ${timeout}s");
}

# temprm($ip) -> (ok, message)  (removes from both temp sets)
sub temprm {
    my ($self, $ip) = @_;
    my $p = parse($ip) or return (0, "csf: [$ip] is not a valid IP or CIDR");
    my ($ok, $msg) = $self->{state}->temp_remove($p->{canonical});
    if ($self->{nft}->table_exists()) {
        $self->{nft}->del_element($self->_temp_set($p->{set}),  $p->{canonical});
        $self->{nft}->del_element($self->_tallow_set($p->{set}), $p->{canonical});
    }
    return ($ok, $ok ? "csf: removed temporary entry for $p->{canonical}" : $msg);
}

# snapshot_save($file) -> (ok, msg)
# Capture the current live table as a self-contained rollback script on disk.
sub snapshot_save {
    my ($self, $file) = @_;
    my ($ok, $script) = $self->{nft}->save_or_capture();
    return (0, 'could not capture current ruleset') unless $ok;
    open my $fh, '>', $file or return (0, "open $file: $!");
    print {$fh} ($script // q{});
    close $fh;
    return (1, $file);
}

# revert_from($file) -> (ok, msg)
# Re-apply a previously captured snapshot (used by the safe-reload watchdog).
sub revert_from {
    my ($self, $file) = @_;
    return (0, "no snapshot at $file") unless -e $file;
    open my $fh, '<', $file or return (0, "open $file: $!");
    my $script = do { local $/; <$fh> };
    close $fh;
    if (!defined $script || $script !~ /\S/) {
        # empty snapshot => the table did not exist before; remove it.
        $self->{nft}->delete_table();
        return (1, 'reverted (removed csf table)');
    }
    my ($ok, $out) = $self->{nft}->apply($script);
    return ($ok ? 1 : 0, $ok ? 'reverted to previous ruleset' : "revert failed: $out");
}

# inspect($ip) -> \%info  (state across all lists + live sets)
sub inspect {
    my ($self, $ip) = @_;
    my $p = parse($ip) or return { error => "invalid address: $ip" };
    my %info = (ip => $p->{canonical}, type => $p->{type}, state => 'clear', where => []);
    if (my $c = $self->{state}->in_list('allow', $p->{canonical})) {
        $info{state} = 'allowed'; push @{$info{where}}, "allow list";
    }
    if (my $c = $self->{state}->in_list('deny', $p->{canonical})) {
        $info{state} = 'blocked'; push @{$info{where}}, "deny list";
    }
    for my $t (@{ $self->{state}->temp_load() }) {
        next if $t->{ip} ne $p->{canonical} || $t->{expired};
        $info{state} = $t->{kind} eq 'allow' ? 'allowed' : 'blocked';
        push @{$info{where}}, "temp $t->{kind} (expires in ".($t->{expires}-time)."s)";
        $info{comment} = $t->{comment} if $t->{comment};
    }
    return \%info;
}

1;
