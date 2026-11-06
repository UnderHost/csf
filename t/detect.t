use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use CSF2::Detect;

my $d = CSF2::Detect->new;

sub one { my @e = $d->scan($_[0]); return $e[0] }

# --- SSH ---
{
    my $e = one('May 12 10:00:01 web01 sshd[2931]: Failed password for root from 185.203.44.19 port 55234 ssh2');
    ok($e, 'ssh failed password matched');
    is($e->{source_ip}, '185.203.44.19', 'ssh ip');
    is($e->{service}, 'sshd', 'ssh service');
    is($e->{event}, 'auth_failure', 'ssh event');
    is($e->{username}, 'root', 'ssh user');
    is($e->{severity}, 10, 'ssh severity');
}
{
    my $e = one('sshd[1]: Invalid user admin from 45.9.148.7');
    is($e->{event}, 'invalid_user', 'invalid user event');
    is($e->{source_ip}, '45.9.148.7', 'invalid user ip');
}
{
    my $e = one('sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9');
    is($e->{source_ip}, '203.0.113.9', 'pam auth failure rhost ip');
}
{
    my $e = one('sshd[1]: Failed password for root from 2001:db8::bad port 22 ssh2');
    is($e->{source_ip}, '2001:db8::bad', 'IPv6 ssh ip captured');
}

# --- Exim SMTP AUTH ---
{
    my $e = one('2026-01-01 dovecot_login authenticator failed for (x) [45.9.148.7]: 535 Incorrect authentication data');
    is($e->{service}, 'exim', 'exim service');
    is($e->{event}, 'smtp_auth_failure', 'smtp auth failure');
    is($e->{source_ip}, '45.9.148.7', 'exim ip from brackets');
}

# --- Dovecot ---
{
    my $e = one('imap-login: Info: Aborted login (auth failed, 3 attempts): user=<a>, method=PLAIN, rip=198.51.100.22, lip=10.0.0.1');
    is($e->{service}, 'dovecot', 'dovecot service');
    is($e->{source_ip}, '198.51.100.22', 'dovecot rip ip');
}

# --- cPanel ---
{
    my $e = one('cphulkd: FAILED LOGIN for user root from 45.9.148.7');
    is($e->{service}, 'cpanel', 'cpanel service');
    is($e->{event}, 'panel_login_failure', 'panel login failure');
    is($e->{source_ip}, '45.9.148.7', 'cpanel ip');
    is($e->{severity}, 15, 'cpanel severity higher');
}

# --- WordPress access log ---
{
    my $e = one('45.9.148.7 - - [01/Jan/2026:00:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 1234');
    is($e->{service}, 'wordpress', 'wp service');
    is($e->{event}, 'wp_login_probe', 'wp login probe');
    is($e->{source_ip}, '45.9.148.7', 'wp ip');
}

# --- IPv4 with :port gets stripped ---
{
    my $d2 = CSF2::Detect->new(rules => [
        { service=>'x', event=>'e', severity=>1, port=>1, re=>qr/from (?<ip>[0-9.]+:\d+)/ }
    ]);
    my @e = $d2->scan('conn from 1.2.3.4:5555');
    is($e[0]{source_ip}, '1.2.3.4', 'ipv4:port stripped to ip');
}

# --- non-matching line yields nothing ---
is(scalar($d->scan('Jan 1 00:00:00 web01 systemd[1]: Started Session 1 of user root.')), 0, 'benign line ignored');

# --- invalid ip capture rejected ---
{
    my $d3 = CSF2::Detect->new(rules => [
        { service=>'x', event=>'e', severity=>1, port=>1, re=>qr/from (?<ip>\S+)/ }
    ]);
    is(scalar($d3->scan('from 999.999.1.1')), 0, 'invalid ip not emitted');
}

done_testing();
