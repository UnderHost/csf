package CSF2::Version;

###############################################################################
# CSF 2.0 - Core Shield Firewall
# CSF2::Version - the CSF version, read from the single VERSION file at the top
# of the tree (installed as /usr/local/csf/VERSION). A release changes that one
# file; the CLI, the web interface, the installer and the tests all follow it.
#
# Copyright (C) 2026 CSF - Core Shield Firewall (GNU GPL v3).
###############################################################################

use strict;
use warnings;
use File::Basename qw(dirname);
use File::Spec;

my $cached;

sub version {
    return $cached if defined $cached;
    my $top = dirname(dirname(dirname(File::Spec->rel2abs(__FILE__))));   # lib/CSF2/Version.pm -> tree
    for my $f ("$top/VERSION", '/usr/local/csf/VERSION') {
        open(my $fh, '<', $f) or next;
        my $v = <$fh>;
        close $fh;
        return $cached = $1 if defined $v && $v =~ /^\s*(\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)\s*$/;
    }
    return $cached = '0.0.0';
}

1;
