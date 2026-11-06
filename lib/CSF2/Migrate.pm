package CSF2::Migrate;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Migrate - migrate a legacy CSF (v15.x / ConfigServer Security &
# Firewall) install to CSF 2.0.
#
# Principles (from the design brief):
#   * Never silently discard security settings. Everything is carried over
#     unless it is genuinely obsolete, and every decision is reported.
#   * Back up the legacy config before touching anything.
#   * Preserve allowlists / denylists / ignore lists, canonicalised + deduped.
#   * Deprecated iptables/ipset knobs are dropped WITH an explanation.
#
# analyze() is pure (no writes) so the mapping is fully unit-tested; backup()
# and write_config()/import_lists() perform the side effects.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use File::Path qw(make_path);
use File::Copy qw(copy);
use CSF2::Config;
use CSF2::IP qw(parse);

# Legacy keys that no longer apply under the native nftables engine.
our %DEPRECATED = (
    IPTABLES       => 'nftables engine - iptables path not used',
    IP6TABLES      => 'nftables engine - ip6tables path not used',
    IPTABLESWAIT   => 'nftables transactions are atomic; wait flag obsolete',
    IPSET          => 'native nftables sets replace ipset',
    USE_IPSET      => 'native nftables sets are always used',
    LF_IPSET_HASHSIZE => 'nftables set sizing is automatic',
    LF_IPSET_MAXELEM  => 'nftables set sizing is automatic',
    WAITLOCK       => 'nftables locking is handled by the kernel',
    WAITLOCK_TIMEOUT  => 'not applicable to nftables',
    FASTSTART      => 'nftables full-load is already atomic and fast',
    LF_IPSET       => 'native nftables sets replace ipset',
    # legacy integrated UI (own TLS server, plaintext UI_PASS) - replaced by csf2-ui
    map { $_ => "legacy integrated UI replaced by csf2-ui (csf --ui-user)" }
        qw(UI UI_PORT UI_IP UI_USER UI_PASS UI_ALLOW UI_BAN UI_BLOCK UI_RETRY UI_TIMEOUT
           UI_CHILDREN UI_ALERT UI_CIPHER UI_SSL_VERSION UI_CXS UI_CSE),
);

# Legacy keys carried over unchanged (same meaning in CSF 2.0).
our %DIRECT = map { $_ => 1 } qw(
    TESTING IPV6 TCP_IN UDP_IN TCP_OUT UDP_OUT TCP6_IN UDP6_IN TCP6_OUT UDP6_OUT
    LF_PARSE LF_ALERT_TO LF_ALERT_FROM LF_EMAIL_ALERT
    DENY_IP_LIMIT DENY_TEMP_IP_LIMIT
    CT_LIMIT CT_INTERVAL CT_PORTS
    LF_DSHIELD SMTP_BLOCK
);

# Legacy keys mapped to a new CSF 2.0 key (converted).
our %CONVERTED = (
    # legacy per-service trigger stays as a reference default; the scoring
    # model (CSF2::Risk) supersedes it, but we keep the value for continuity.
    LF_TRIGGER => 'RISK_LEGACY_TRIGGER',
);

sub new {
    my ($class, %opts) = @_;
    my $self = {
        legacy_etc => $opts{legacy_etc} || '/etc/csf',
        target_etc => $opts{target_etc} || '/etc/csf',
        backup_dir => $opts{backup_dir},
    };
    return bless $self, $class;
}

###############################################################################
# _read_conf($file) -> \%kv  (legacy csf.conf KEY = "value")
sub _read_conf {
    my ($file) = @_;
    my %kv;
    return \%kv unless -e $file;
    open my $fh, '<', $file or return \%kv;
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        if (/^\s*([A-Z0-9_]+)\s*=\s*"?(.*?)"?\s*$/) { $kv{$1} = $2 }
    }
    close $fh;
    return \%kv;
}

###############################################################################
# analyze() -> (\%new_config, \%report)
# report buckets: migrated, converted, deprecated, manual, errors (arrayrefs of
# human-readable strings) plus counts.
sub analyze {
    my ($self) = @_;
    my $legacy = _read_conf("$self->{legacy_etc}/csf.conf");
    my %new = %CSF2::Config::DEFAULTS;   # start from 2.0 defaults
    my %report = (migrated=>[], converted=>[], deprecated=>[], manual=>[], errors=>[]);

    for my $key (sort keys %$legacy) {
        my $val = $legacy->{$key};
        if ($DEPRECATED{$key}) {
            push @{$report{deprecated}}, "$key dropped: $DEPRECATED{$key}";
            next;
        }
        if ($CONVERTED{$key}) {
            my $nk = $CONVERTED{$key};
            $new{$nk} = $val;
            push @{$report{converted}}, "$key -> $nk ($val)";
            next;
        }
        if ($DIRECT{$key}) {
            $new{$key} = $val;
            push @{$report{migrated}}, "$key = $val";
            next;
        }
        # LF_* detection thresholds: carried over but flagged for review under
        # the new scoring model.
        if ($key =~ /^LF_/) {
            $new{$key} = $val;
            push @{$report{manual}}, "$key = $val (review under CSF 2.0 risk scoring)";
            next;
        }
        # Unknown/other keys: preserve verbatim so nothing is silently lost.
        $new{$key} = $val;
        push @{$report{migrated}}, "$key = $val (preserved)";
    }

    # Ensure 2.0 invariants are present.
    $new{CONFIG_VERSION} = $CSF2::Config::CONFIG_VERSION;
    $new{INPUT_POLICY} ||= 'drop';
    $new{MGMT_PORTS}   ||= '22,2087,2083,2086,2082';
    $new{NFT}          ||= '/usr/sbin/nft';

    for my $b (qw(migrated converted deprecated manual errors)) {
        $report{"count_$b"} = scalar @{ $report{$b} };
    }
    return (\%new, \%report);
}

###############################################################################
# backup() -> (ok, path)  copy the whole legacy /etc/csf aside.
sub backup {
    my ($self) = @_;
    my $dir = $self->{backup_dir}
              || ("$self->{legacy_etc}/backup/pre-csf2-" . _stamp());
    make_path($dir) unless -d $dir;
    my $ok = 1;
    for my $f (qw(csf.conf csf.allow csf.deny csf.ignore csf.pignore csf.rignore
                  csf.dyndns csf.blocklists csf.logfiles)) {
        my $src = "$self->{legacy_etc}/$f";
        next unless -e $src;
        copy($src, "$dir/$f") or do { $ok = 0 };
    }
    return ($ok, $dir);
}

###############################################################################
# import_lists() -> \%counts  (allow/deny/ignore, canonicalised + deduped)
# Returns { allow, deny, ignore } counts written to the target etc.
sub import_lists {
    my ($self) = @_;
    my %counts;
    for my $name (qw(allow deny ignore)) {
        my $src = "$self->{legacy_etc}/csf.$name";
        my $dst = "$self->{target_etc}/csf.$name";
        my (%seen, @out);
        if (-e $src) {
            open my $in, '<', $src or next;
            while (my $line = <$in>) {
                chomp $line;
                next if $line =~ /^\s*#/ || $line =~ /^\s*$/;
                my ($tok, $comment) = split /\s*#\s*/, $line, 2;
                $tok =~ s/^\s+|\s+$//g;
                my $p = parse($tok);
                if (!$p) { push @out, $line; next }   # keep non-IP directives as-is
                next if $seen{$p->{canonical}}++;
                push @out, $p->{canonical} . (defined $comment && $comment ne '' ? " # $comment" : '');
            }
            close $in;
        }
        make_path($self->{target_etc}) unless -d $self->{target_etc};
        open my $o, '>', $dst or next;
        print {$o} join("\n", @out), (@out ? "\n" : '');
        close $o;
        $counts{$name} = scalar @out;
    }
    return \%counts;
}

###############################################################################
# write_config(\%new_config) -> (ok, path)   write target csf.conf
sub write_config {
    my ($self, $new) = @_;
    my $file = "$self->{target_etc}/csf.conf";
    make_path($self->{target_etc}) unless -d $self->{target_etc};
    open my $fh, '>', $file or return (0, "open $file: $!");
    print {$fh} "# CSF 2.0 configuration - migrated from legacy CSF\n";
    print {$fh} "# Generated " . localtime() . "\n\n";
    for my $k (sort keys %$new) {
        my $v = defined $new->{$k} ? $new->{$k} : '';
        $v = join(',', @$v) if ref $v eq 'ARRAY';
        print {$fh} qq{$k = "$v"\n};
    }
    close $fh;
    return (1, $file);
}

sub _stamp {
    my @t = localtime;
    return sprintf('%04d%02d%02d-%02d%02d%02d', $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
}

1;
