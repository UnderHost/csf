use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use CSF2::Nft;

my $nft = CSF2::Nft->new(dry_run => 1, nft => '/usr/sbin/nft');

# helper: last recorded argv joined
sub last_cmd { my $l = $nft->log; return join(' ', @{ $l->[-1] }) }

# add_element (permanent deny)
my ($ok) = $nft->add_element('csf_deny4', '185.203.44.19');
ok($ok == 1, 'add_element returns ok in dry-run');
is(last_cmd(), '/usr/sbin/nft add element inet csf csf_deny4 { 185.203.44.19 }',
   'add_element builds correct nft argv');

# add multiple
$nft->add_element('csf_allow4', '1.1.1.1', '2.2.2.2');
is(last_cmd(), '/usr/sbin/nft add element inet csf csf_allow4 { 1.1.1.1, 2.2.2.2 }',
   'add_element joins multiple elements');

# add_timeout (temp ban with native timeout)
$nft->add_timeout('csf_temp4', '10.0.0.9', 3600);
is(last_cmd(), '/usr/sbin/nft add element inet csf csf_temp4 { 10.0.0.9 timeout 3600s }',
   'add_timeout builds timeout element');

# default timeout
$nft->add_timeout('csf_temp6', '2001:db8::9');
is(last_cmd(), '/usr/sbin/nft add element inet csf csf_temp6 { 2001:db8::9 timeout 3600s }',
   'add_timeout default 3600s');

# del_element
$nft->del_element('csf_deny4', '185.203.44.19');
is(last_cmd(), '/usr/sbin/nft delete element inet csf csf_deny4 { 185.203.44.19 }',
   'del_element builds delete argv');

# validate / apply feed stdin
my ($vok) = $nft->validate("table inet csf {}");
ok($vok, 'validate ok in dry-run');
is(join(' ', @{ $nft->log->[-1] }), '/usr/sbin/nft -c -f - <<stdin>>', 'validate uses -c -f -');

$nft->apply("table inet csf {}");
is(join(' ', @{ $nft->log->[-1] }), '/usr/sbin/nft -f - <<stdin>>', 'apply uses -f -');

# delete_table
$nft->delete_table();
is(last_cmd(), '/usr/sbin/nft delete table inet csf', 'delete_table argv');

# LIST FORM SAFETY: an attacker-shaped string is a single argv token, never shell.
# (Callers validate first; this proves the driver adds no shell surface.)
$nft->add_element('csf_deny4', '1.2.3.4; rm -rf /');
my $l = $nft->log->[-1];
is($l->[-1], '{ 1.2.3.4; rm -rf / }', 'malicious element stays one argv token (no shell)');
is(scalar(@$l), 7, 'argv is a fixed-arity list, not a concatenated command');

done_testing();
