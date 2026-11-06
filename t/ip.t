use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use CSF2::IP qw(checkip family normalize checkcidr is_ip is_cidr parse nft_family);

# --- checkip: valid IPv4 ---
is(checkip('1.2.3.4'), 4, 'plain IPv4');
is(checkip('192.168.0.255'), 4, 'IPv4 with 255 octet');
is(checkip('0.0.0.0'), 4, 'IPv4 zero');

# --- checkip: invalid IPv4 ---
is(checkip('256.1.1.1'), 0, 'octet > 255 rejected');
is(checkip('1.2.3'), 0, 'short IPv4 rejected');
is(checkip('1.2.3.4.5'), 0, 'long IPv4 rejected');
is(checkip('1.2.3.4/24'), 0, 'CIDR rejected by checkip');
is(checkip('hello'), 0, 'garbage rejected');
is(checkip(''), 0, 'empty rejected');
is(checkip(undef), 0, 'undef rejected');

# --- checkip: valid IPv6 ---
is(checkip('2001:db8::1'), 6, 'compressed IPv6');
is(checkip('::1'), 6, 'IPv6 loopback');
is(checkip('fe80::1'), 6, 'IPv6 link-local');
is(checkip('2001:0db8:0000:0000:0000:0000:0000:0001'), 6, 'full IPv6');

# --- checkip: invalid IPv6 ---
is(checkip('2001:db8::z'), 0, 'bad IPv6 hextet');
is(checkip(':::'), 0, 'triple colon rejected');

# --- normalize: canonical, dedup-safe ---
is(normalize('2001:0db8:0000:0000:0000:0000:0000:0001'), '2001:db8::1', 'IPv6 compressed');
is(normalize('2001:DB8::1'), '2001:db8::1', 'IPv6 lower-cased');
# IPv4-mapped IPv6 renders in the standard mixed form; the point is that it is
# deterministic, so both spellings collapse to one stored value.
is(normalize('::FFFF:0:0'), normalize('::ffff:0:0'), 'IPv4-mapped IPv6 deterministic');
# Leading-zero octets are ambiguous (octal) and rejected on every platform.
is(checkip('185.203.44.019'), 0, 'IPv4 leading-zero octet rejected');
is(normalize('01.02.03.04'), undef, 'IPv4 leading zeros rejected (ambiguous)');
is(normalize('192.168.0.1'), '192.168.0.1', 'plain IPv4 normalizes unchanged');
# The two spellings below must collapse to ONE canonical string.
is(normalize('2001:db8::1'), normalize('2001:0db8::0001'), 'equivalent IPv6 dedup');
is(normalize('bad'), undef, 'invalid normalize -> undef');

# --- family() accepts IP or CIDR ---
is(family('1.2.3.4'), 4, 'family plain v4');
is(family('2001:db8::/32'), 6, 'family v6 CIDR');
is(family('nope'), 0, 'family invalid');

# --- checkcidr ---
is_deeply([checkcidr('10.0.0.0/8')], [4, '10.0.0.0/8'], 'v4 CIDR ok');
is_deeply([checkcidr('2001:DB8::/32')], [6, '2001:db8::/32'], 'v6 CIDR canonicalised');
is((checkcidr('1.2.3.4/33'))[0], 0, 'v4 prefix > 32 rejected');
is((checkcidr('2001:db8::/129'))[0], 0, 'v6 prefix > 128 rejected');
is((checkcidr('1.2.3.4/8/9'))[0], 0, 'double slash rejected');
is((checkcidr('1.2.3.4'))[0], 0, 'plain IP rejected by checkcidr');

# --- is_ip / is_cidr ---
ok(is_ip('1.2.3.4'), 'is_ip true');
ok(!is_ip('1.2.3.4/24'), 'is_ip false on CIDR');
ok(is_cidr('1.2.3.0/24'), 'is_cidr true');
ok(!is_cidr('1.2.3.4'), 'is_cidr false on IP');

# --- parse ---
my $p = parse('2001:0db8::1');
is($p->{type}, 6, 'parse type 6');
is($p->{kind}, 'ip', 'parse kind ip');
is($p->{family}, 'ip6', 'parse nft family ip6');
is($p->{canonical}, '2001:db8::1', 'parse canonical');
is($p->{set}, '6', 'parse set suffix 6');

my $c = parse('10.0.0.0/8');
is($c->{kind}, 'cidr', 'parse cidr kind');
is($c->{family}, 'ip', 'parse cidr family ip');
is($c->{prefix}, '8', 'parse cidr prefix');
is($c->{canonical}, '10.0.0.0/8', 'parse cidr canonical');

is(parse('garbage'), undef, 'parse invalid -> undef');

# --- ip_in_cidr (v4) ---
ok(CSF2::IP::ip_in_cidr('192.168.1.50', '192.168.1.0/24'), 'v4 inside /24');
ok(!CSF2::IP::ip_in_cidr('192.168.2.50', '192.168.1.0/24'), 'v4 outside /24');
ok(CSF2::IP::ip_in_cidr('10.20.30.40', '10.0.0.0/8'), 'v4 inside /8');
ok(CSF2::IP::ip_in_cidr('1.2.3.4', '1.2.3.4/32'), 'v4 /32 exact');
ok(!CSF2::IP::ip_in_cidr('1.2.3.5', '1.2.3.4/32'), 'v4 /32 non-match');
ok(CSF2::IP::ip_in_cidr('1.2.3.4', '0.0.0.0/0'), 'v4 /0 matches all');
ok(CSF2::IP::ip_in_cidr('172.16.5.9', '172.16.4.0/22'), 'v4 non-byte-aligned /22 inside');
ok(!CSF2::IP::ip_in_cidr('172.16.8.9', '172.16.4.0/22'), 'v4 non-byte-aligned /22 outside');

# --- ip_in_cidr (v6) ---
ok(CSF2::IP::ip_in_cidr('2001:db8::1234', '2001:db8::/32'), 'v6 inside /32');
ok(!CSF2::IP::ip_in_cidr('2001:db9::1', '2001:db8::/32'), 'v6 outside /32');
ok(CSF2::IP::ip_in_cidr('2001:db8:abcd::1', '2001:db8:abcd::/48'), 'v6 inside /48');
ok(!CSF2::IP::ip_in_cidr('192.168.1.1', '2001:db8::/32'), 'family mismatch is false');

# --- ip_in_any ---
my $list = ['203.0.113.7', '198.51.100.0/24', '2001:db8::/32'];
is(CSF2::IP::ip_in_any('198.51.100.200', $list), '198.51.100.0/24', 'ip_in_any CIDR hit');
is(CSF2::IP::ip_in_any('203.0.113.7', $list), '203.0.113.7', 'ip_in_any exact hit');
is(CSF2::IP::ip_in_any('2001:db8::99', $list), '2001:db8::/32', 'ip_in_any v6 CIDR hit');
is(CSF2::IP::ip_in_any('8.8.8.8', $list), undef, 'ip_in_any miss');

done_testing();
