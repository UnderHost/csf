use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use CSF2::Detect;
use CSF2::Risk;
use CSF2::LFD;

my $d = CSF2::Detect->new;
sub one { my @e = $d->scan($_[0]); return $e[0] }

# ModSecurity SQLi hit -> waf_sqli, severity 45, metadata carries rule id
{
    my $line = '[Wed Jan 01 00:00:00 2026] [:error] [pid 100] [client 45.9.148.7] ModSecurity: Access denied with code 403 (phase 2). [id "942100"] [msg "SQL Injection Attack Detected"]';
    my $e = one($line);
    ok($e, 'modsec line matched');
    is($e->{service}, 'modsecurity', 'service modsecurity');
    is($e->{event}, 'waf_sqli', 'classified as sqli');
    is($e->{severity}, 45, 'sqli severity 45');
    is($e->{metadata}{rule_id}, '942100', 'rule id captured');
    is($e->{metadata}{confidence}, 'high', 'high confidence');
}

# RCE scores much higher than a generic anomaly
{
    my $rce = one('[client 1.2.3.4] ModSecurity: Access denied [id "932100"] [msg "Remote Command Execution"]');
    is($rce->{event}, 'waf_rce', 'rce classified');
    is($rce->{severity}, 70, 'rce severity 70');
    my $anom = one('[client 1.2.3.4] ModSecurity: Warning [id "999999"] [msg "Unknown"]');
    is($anom->{severity}, 8, 'unknown family -> low anomaly severity');
}

# XSS medium
{
    my $xss = one('[client 9.9.9.9] ModSecurity: Access denied [id "941100"] [msg "XSS Attack"]');
    is($xss->{event}, 'waf_xss', 'xss classified');
    is($xss->{severity}, 35, 'xss severity 35');
}

# waf_category helper (for the WHM UI)
{
    my ($cat, $sev, $conf) = CSF2::Detect::waf_category('932110');
    is($cat, 'rce', 'waf_category rce');
    is($sev, 70, 'waf_category severity');
    is($conf, 'high', 'waf_category confidence');
}

# --- WAF -> firewall escalation through the LFD pipeline ---
# Two RCE probes (70 each) blow past the block threshold; a single hit would too,
# but repetition + high confidence is the intended escalation path.
{
    my $risk = CSF2::Risk->new;   # default T_SHORT_BLOCK=70
    my $lfd  = CSF2::LFD->new(risk => $risk, detect => CSF2::Detect->new);  # no engine (dry logic)
    my $now  = 9_000_000;
    my @a = $lfd->process_line('[client 45.9.148.7] ModSecurity: Access denied [id "932100"] [msg "RCE"]', $now);
    is($a[0]{action}, 'temp', 'single high-severity RCE escalates to a block');
    like($a[0]{reason}, qr/modsecurity waf_rce/, 'reason names the WAF attack');

    # a low-severity protocol warning alone must NOT block
    my $risk2 = CSF2::Risk->new;
    my $lfd2  = CSF2::LFD->new(risk => $risk2, detect => CSF2::Detect->new);
    my @b = $lfd2->process_line('[client 8.8.8.8] ModSecurity: Warning [id "920100"] [msg "protocol"]', $now);
    is($b[0]{action}, 'monitor', 'low-severity WAF anomaly only monitors (false-positive safe)');
}

done_testing();
