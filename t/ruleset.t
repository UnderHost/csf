use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use CSF2::Ruleset;

# --- full build with state ---
my $config = {
    TCP_IN  => '22,80,443,2087',
    UDP_IN  => '53',
    TCP_OUT => '',
    IPV6    => 1,
    ICMP_IN => 1,
};
my $state = {
    allow4 => ['203.0.113.7', '198.51.100.0/24'],
    deny4  => ['185.203.44.19'],
    deny6  => ['2001:db8::bad'],
    temp   => [
        { ip => '10.0.0.9',  family => 4, kind => 'deny',  timeout => 3600 },
        { ip => '10.0.0.10', family => 4, kind => 'allow', timeout => 600  },
        { ip => '2001:db8::9', family => 6, kind => 'deny', timeout => 1800 },
    ],
};

my $s = CSF2::Ruleset::build($config, $state);

# table + atomic replace preamble
like($s, qr/table inet csf \{\}/, 'atomic: create-if-missing');
like($s, qr/delete table inet csf/, 'atomic: delete before recreate');
like($s, qr/table inet csf \{/, 'main table block');

# sets present
for my $set (qw(csf_allow4 csf_allow6 csf_deny4 csf_deny6 csf_temp4 csf_temp6
                csf_tallow4 csf_tallow6 csf_abuse4 csf_abuse6)) {
    like($s, qr/\bset $set \{/, "set $set defined");
}

# set typing + flags
like($s, qr/set csf_deny4 \{\s*\n\s*type ipv4_addr\s*\n\s*flags interval/, 'deny4 interval set');
like($s, qr/set csf_temp4 \{\s*\n\s*type ipv4_addr\s*\n\s*flags timeout/, 'temp4 timeout set');

# inline elements populated from state
like($s, qr/elements = \{ 203\.0\.113\.7, 198\.51\.100\.0\/24 \}/, 'allow4 elements inline');
like($s, qr/csf_deny4.*?elements = \{ 185\.203\.44\.19 \}/s, 'deny4 element inline');

# temp bans carry native timeouts
like($s, qr/10\.0\.0\.9 timeout 3600s/, 'temp deny4 timeout element');
like($s, qr/10\.0\.0\.10 timeout 600s/, 'temp allow4 timeout element');
like($s, qr/2001:db8::9 timeout 1800s/, 'temp deny6 timeout element');

# rule ordering: allow accept before deny drop
ok(index($s, 'ip saddr @csf_allow4 accept') < index($s, 'ip saddr @csf_deny4'),
   'allow evaluated before deny');
like($s, qr/ip saddr \@csf_temp4 drop/, 'temp4 drop rule');
like($s, qr/ct state established,related accept/, 'conntrack accept');
like($s, qr/iif "lo" accept/, 'loopback accept');

# ports
like($s, qr/tcp dport \{ 22, 80, 443, 2087 \} ct state new accept/, 'tcp_in ports');
like($s, qr/udp dport \{ 53 \} accept/, 'udp_in ports');

# ipv6 essential icmp
like($s, qr/icmpv6 type \{[^}]*nd-neighbor-solicit/, 'ICMPv6 ND allowed');

# default drop policy + counter
like($s, qr/policy drop;/, 'input policy drop');
like($s, qr/comment "csf-input-drop"/, 'final drop counter');

# --- IPv6 disabled: no v6 sets/rules emitted ---
my $s4 = CSF2::Ruleset::build({ TCP_IN => '22', IPV6 => 0 }, {});
unlike($s4, qr/csf_deny6/, 'no v6 sets when IPV6=0');
unlike($s4, qr/ip6 saddr/, 'no ip6 rules when IPV6=0');
like($s4, qr/csf_deny4/, 'v4 sets still present when IPV6=0');

# --- restrictive outbound ---
my $so = CSF2::Ruleset::build({ TCP_IN => '22', TCP_OUT => '80,443', IPV6 => 0 }, {});
like($so, qr/tcp dport \{ 80, 443 \} ct state new accept/, 'tcp_out ports');
like($so, qr/ct state new drop/, 'outbound default drop when TCP_OUT set');

# --- set_names helper (10 core + 6 threat-intel sets) ---
is(scalar(CSF2::Ruleset::set_names(1)), 16, 'set_names v6 -> 16 sets');
is(scalar(CSF2::Ruleset::set_names(0)), 8,  'set_names v4-only -> 8 sets');

# --- threat-intelligence rules: only emitted when TI_ENABLE ---
my $noti = CSF2::Ruleset::build({ TCP_IN => '22', IPV6 => 1 }, {});
unlike($noti, qr/csf_ti_high4 drop/, 'no TI drop rules when TI disabled');
like($noti, qr/set csf_ti_high4 \{/, 'TI sets always defined (empty until fed)');

my $ti = CSF2::Ruleset::build({ TCP_IN => '22', IPV6 => 1, TI_ENABLE => 1 }, {});
like($ti, qr/ip saddr \@csf_ti_high4 drop/, 'TI high inbound drop');
like($ti, qr/ip saddr \@csf_ti_attackers4 drop/, 'TI attackers inbound drop');
like($ti, qr/ip6 saddr \@csf_ti_botnet6 drop/, 'TI botnet inbound drop (v6)');
like($ti, qr/ip daddr \@csf_ti_botnet4 drop/, 'TI botnet OUTBOUND drop (C2 protection)');
like($ti, qr/ip daddr \@csf_ti_high4 drop/, 'TI high outbound drop');
# outbound TI drop sits before the OUTPUT chain's established-accept so active
# C2 links are cut (there are two established-accept lines; check within output)
my ($outchain) = $ti =~ /chain output \{(.*?)\n\t\}/s;
ok($outchain && index($outchain, 'ip daddr @csf_ti_botnet4 drop') >= 0
   && index($outchain, 'ip daddr @csf_ti_botnet4 drop') < index($outchain, 'ct state established,related accept'),
   'outbound TI drop precedes established-accept in the output chain');

done_testing();
