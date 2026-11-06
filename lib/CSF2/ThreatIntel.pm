package CSF2::ThreatIntel;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::ThreatIntel - automated threat-intelligence feed manager.
#
# Downloads reputable IP/CIDR reputation feeds and loads them into DEDICATED
# nftables sets (never into csf.deny, which would bloat and reload poorly).
# Feeds are grouped by category, each with a blocking policy:
#
#   high      (Spamhaus DROP)      -> csf_ti_high{4,6}      block inbound + outbound
#   botnet    (Feodo C2)           -> csf_ti_botnet{4,6}    block outbound (+ inbound)
#   attackers (CINS/IPsum/BL.de)   -> csf_ti_attackers{4,6} block inbound
#
# Each feed can be toggled on/off per vendor via csf.conf (TI_<ID> = 0|1).
# Parsing is pure + unit-tested; downloading and set-loading are side effects.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use CSF2::IP qw(parse);

# Category -> nftables sets + policy (used by the ruleset builder).
our %CATEGORY = (
    high      => { set4 => 'csf_ti_high4',      set6 => 'csf_ti_high6',      policy => 'inout' },
    botnet    => { set4 => 'csf_ti_botnet4',    set6 => 'csf_ti_botnet6',    policy => 'out'   },
    attackers => { set4 => 'csf_ti_attackers4', set6 => 'csf_ti_attackers6', policy => 'in'    },
);

# Feed registry. `default` = enabled out of the box. `interval` is advisory
# (the cron runs a single --ti-update; feeds refresh at their own cadence
# upstream). No static threat-actor names - only actionable indicators.
our @FEEDS = (
    { id=>'spamhaus_drop4', name=>'Spamhaus DROP (IPv4)',   vendor=>'Spamhaus',
      url=>'https://www.spamhaus.org/drop/drop_v4.json', format=>'spamhaus_json',
      family=>4, category=>'high', default=>1, interval=>'daily' },
    { id=>'spamhaus_drop6', name=>'Spamhaus DROP (IPv6)',   vendor=>'Spamhaus',
      url=>'https://www.spamhaus.org/drop/drop_v6.json', format=>'spamhaus_json',
      family=>6, category=>'high', default=>1, interval=>'daily' },
    { id=>'feodo',          name=>'Feodo Tracker (Botnet C2)', vendor=>'abuse.ch',
      url=>'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', format=>'plaintext',
      family=>4, category=>'botnet', default=>1, interval=>'15m' },
    { id=>'cins',           name=>'CINS Army (Active attackers)', vendor=>'CINS',
      url=>'https://cinsscore.com/list/ci-badguys.txt', format=>'plaintext',
      family=>4, category=>'attackers', default=>1, interval=>'hourly' },
    { id=>'ipsum3',         name=>'IPsum (3+ feeds)',       vendor=>'IPsum',
      url=>'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt', format=>'plaintext',
      family=>4, category=>'attackers', default=>1, interval=>'daily' },
    { id=>'blocklist_all',  name=>'Blocklist.de (All)',     vendor=>'Blocklist.de',
      url=>'https://lists.blocklist.de/lists/all.txt', format=>'plaintext',
      family=>4, category=>'attackers', default=>0, interval=>'30m' },
    { id=>'blocklist_ssh',  name=>'Blocklist.de (SSH)',     vendor=>'Blocklist.de',
      url=>'https://lists.blocklist.de/lists/ssh.txt', format=>'plaintext',
      family=>4, category=>'attackers', default=>0, interval=>'30m' },
    { id=>'blocklist_mail', name=>'Blocklist.de (Mail)',    vendor=>'Blocklist.de',
      url=>'https://lists.blocklist.de/lists/mail.txt', format=>'plaintext',
      family=>4, category=>'attackers', default=>0, interval=>'30m' },
    { id=>'blocklist_web',  name=>'Blocklist.de (Web)',     vendor=>'Blocklist.de',
      url=>'https://lists.blocklist.de/lists/apache.txt', format=>'plaintext',
      family=>4, category=>'attackers', default=>0, interval=>'30m' },
);

sub feeds { return @FEEDS }
sub feed  { my ($id) = @_; for (@FEEDS) { return $_ if $_->{id} eq $id } return undef }

# feed_enabled(\%cfg, $feed) -> bool. Master switch TI_ENABLE + per-feed TI_<ID>.
sub feed_enabled {
    my ($cfg, $f) = @_;
    return 0 unless $cfg->{TI_ENABLE};
    my $key = 'TI_' . uc($f->{id});
    return exists $cfg->{$key} ? ($cfg->{$key} ? 1 : 0) : ($f->{default} ? 1 : 0);
}

# sets_for_family($fam) / all_sets() - the nftables sets TI owns.
sub all_sets {
    my @s;
    for my $c (values %CATEGORY) { push @s, $c->{set4}, $c->{set6} }
    return @s;
}

###############################################################################
# parse_feed($content, $format) -> \@canonical_entries (validated, deduped)
# Handles Spamhaus newline-delimited JSON ({"cidr":"..."}) and plaintext feeds
# (IP/CIDR per line, comments after # or ; stripped, extra columns ignored).
sub parse_feed {
    my ($content, $format) = @_;
    $content = '' unless defined $content;
    my (@out, %seen);
    if (($format || '') eq 'spamhaus_json') {
        while ($content =~ /"cidr"\s*:\s*"([^"]+)"/g) {
            my $p = parse($1) or next;
            next if $seen{$p->{canonical}}++;
            push @out, $p->{canonical};
        }
    } else {
        for my $line (split /\r?\n/, $content) {
            $line =~ s/[#;].*//;               # strip comments
            $line =~ s/^\s+|\s+$//g;
            next if $line eq '';
            my ($tok) = split /\s+/, $line;     # first column only (IPsum: "IP count")
            my $p = parse($tok) or next;
            next if $seen{$p->{canonical}}++;
            push @out, $p->{canonical};
        }
    }
    return \@out;
}

###############################################################################
# update(%opts) -> \%report
#   nft      => CSF2::Nft, cfg => \%config, var => runtime dir,
#   fetch    => coderef($url) -> $content  (injectable for testing),
#   only     => \@feed_ids (optional subset)
#
# Downloads each enabled feed, parses it, and loads its entries into the
# category set (merging IPv4 feeds that share a set). Returns per-feed results
# and writes a status file. Never touches csf.deny.
sub update {
    my (%o) = @_;
    my $nft = $o{nft}; my $cfg = $o{cfg} || {}; my $var = $o{var} || '/var/lib/csf';
    my $fetch = $o{fetch} || \&_curl;
    my %only = $o{only} ? map { $_ => 1 } @{ $o{only} } : ();

    my %bucket;   # set-name => { entries... }  (merge feeds sharing a set)
    my @report;
    for my $f (@FEEDS) {
        next if %only && !$only{$f->{id}};
        next unless feed_enabled($cfg, $f);
        my $content = eval { $fetch->($f->{url}) };
        if (!defined $content || $content eq '') {
            push @report, { id=>$f->{id}, ok=>0, count=>0, error=>'download failed' };
            next;
        }
        my $entries = parse_feed($content, $f->{format});
        my $cat = $CATEGORY{ $f->{category} };
        my $set = $f->{family} == 6 ? $cat->{set6} : $cat->{set4};
        $bucket{$set}{$_} = 1 for @$entries;
        push @report, { id=>$f->{id}, ok=>1, count=>scalar(@$entries), set=>$set };
    }

    # load each affected set atomically (flush + add)
    my %loaded;
    if ($nft) {
        for my $set (sort keys %bucket) {
            my @e = sort keys %{ $bucket{$set} };
            my ($ok) = $nft->load_set($set, \@e);
            $loaded{$set} = { ok=>$ok, count=>scalar(@e) };
        }
        # empty out any TI set that had no enabled feed this run
        for my $set (all_sets()) {
            next if $bucket{$set};
            $nft->load_set($set, []) if $nft->table_exists;
        }
    }

    _write_status($var, \@report, \%loaded);
    my $total = 0; $total += $_->{count} for grep { $_->{ok} } @report;
    return { feeds=>\@report, loaded=>\%loaded, total=>$total };
}

###############################################################################
# status($var) -> \%status   (last-update summary for the UI/CLI)
sub status {
    my ($var) = @_;
    my $f = "$var/ti.status";
    my %s = (feeds=>[], updated=>0, total=>0);
    return \%s unless -e $f;
    open my $fh, '<', $f or return \%s;
    while (my $l = <$fh>) {
        chomp $l;
        if ($l =~ /^updated\|(\d+)\|(\d+)/) { $s{updated}=$1; $s{total}=$2 }
        elsif ($l =~ /^feed\|(\S+)\|(\d)\|(\d+)/) { push @{$s{feeds}}, { id=>$1, ok=>$2, count=>$3 } }
    }
    close $fh;
    return \%s;
}

sub _write_status {
    my ($var, $report, $loaded) = @_;
    my $total = 0; $total += $_->{count} for grep { $_->{ok} } @$report;
    open my $fh, '>', "$var/ti.status" or return;
    print {$fh} "updated|" . time . "|$total\n";
    for my $r (@$report) {
        print {$fh} join('|', 'feed', $r->{id}, ($r->{ok}?1:0), ($r->{count}||0)) . "\n";
    }
    close $fh;
    return;
}

sub _curl {
    my ($url) = @_;
    $url =~ s/[^A-Za-z0-9:\/._?=&%-]//g;   # sanitise before shelling out
    my $curl = (-x '/usr/bin/curl') ? '/usr/bin/curl' : 'curl';
    my $out = `$curl -fsSL --max-time 30 "$url" 2>/dev/null`;
    return $out;
}

1;
