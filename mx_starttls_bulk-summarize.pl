#!/usr/bin/env perl
# Copyright 2014 Steffen Ullrich <sullr@cpan.org>
#   This program is free software; you can redistribute it and/or
#   modify it under the same terms as Perl itself.
#
# Usage: program < output_from_mx_starttls_bulk


use strict;
use warnings;

my %stat;
while (<>) {
    chop;
    my ($dom,$result,$info) = split(' ',$_,3);
    my @info = $info ? $info =~m{([+-]tls:.*?)(?=$|;[+-]tls:)}g :();
    $stat{total}++;
    if (!@info) {
	$stat{'notls.total'}++;
	if ($result =~m{^-nomx}) {
	    $stat{'total.nomx'}++
	} elsif ($result =~m{^-no-starttls}) {
	    $stat{'total.no-starttls'}++
	} else {
	    $stat{'total.notls'}++
	}
    } else {
	$stat{'total.tls'}++;
	if ($result =~m{^-(?!tls)}) {
	    for(@info) {
		m{^\+(.*)} or next;
		$result = $1;
		last;
	    }
	}
	if ( my ($hv,$v,$c) = $result =~m{^tls:([^\s:]+):([^/]+)/([^/]+)}) {
	    if ($hv eq 'SSLv23') {
		$stat{'tls.initial'}++;
	    } else {
		$stat{'tls.downgrade'}++;
	    }
	    $stat{"tls.$v"}++;
	    $stat{"tls.$c"}++;
	    $stat{"tls.$1"}++ if $c =~m{^((EC)?DHE)-};
	    $stat{"tls.$1"}++ if $c =~m{(RC4)-};
	} elsif ( $result =~m{^-tls}) {
	    $stat{'tls.fail'}++;
	}

	for(@info) {
	    $stat{"tls.fail.$1"}++ if m{^-tls:([\w\-]+)};
	}

    }
}

print process();


sub process {
    my $total = $stat{total};
    my $tls_total = $stat{'total.tls'};
    my $percent = sub {	
	my ($v,$t) = @_;
	return '-' if !$t;
	return 0 if !$v;
	my $p = 100*$v/$t;
	my $f = 10 ** (2-int(log($p)/log(10)));
	return int($p*$f+0.5)/$f;
    };
    for( keys %stat) {
	if (m{^total\.}) {
	    $stat{"$_.percent"} = $percent->($stat{$_},$total);
	} elsif (m{^tls\.}) {
	    $stat{"$_.percent"} = $percent->($stat{$_},$tls_total);
	}
    }

    my $t = template();
    $t =~s{%{(?:([\w\.]+):)?([\w\-\.]+)}}{ sprintf( $1?"%".$1:"%s",$stat{$2}||0) }esg;
    $t;
}

sub template { return <<'TEMPLATE'; }
Total domains: %{total}
No MX record:             %{10d:total.nomx} (%{total.nomx.percent}%)
No STARTTLS:              %{10d:total.no-starttls} (%{total.no-starttls.percent}%)
TLS available:            %{10d:total.tls} (%{total.tls.percent}%)

--- TLS analysis (relativ to TLS domains) ---

TLS initial success:      %{10d:tls.initial} (%{tls.initial.percent}%)
TLS after downgrade:      %{10d:tls.downgrade} (%{tls.downgrade.percent}%)
TLS total fail:           %{10d:tls.fail} (%{tls.fail.percent}%)

TLS common problems:
TLS1.1+ required:         %{10d:tls.fail.notls10} (%{tls.fail.notls10.percent}%)
Only TLS1.2 ciphers:      %{10d:tls.fail.no-v3-ciphers} (%{tls.fail.no-v3-ciphers.percent}%)
Croak on MD5 client cert: %{10d:tls.fail.croak-md5-client-cert} (%{tls.fail.croak-md5-client-cert.percent}%)

TLS protocols used:
TLS1.2:                   %{10d:tls.TLSv1_2} (%{tls.TLSv1_2.percent}%)
TLS1.1:                   %{10d:tls.TLSv1_1} (%{tls.TLSv1_1.percent}%)
TLS1.0:                   %{10d:tls.TLSv1} (%{tls.TLSv1.percent}%)
SSL3.0:                   %{10d:tls.SSLv3} (%{tls.SSLv3.percent}%)

Ciphers used:
ECDHE-* (PFS)             %{10d:tls.ECDHE} (%{tls.ECDHE.percent}%)
DHE-* (PFS)               %{10d:tls.DHE} (%{tls.DHE.percent}%)
RC4 (bad)                 %{10d:tls.RC4} (%{tls.RC4.percent}%)

TEMPLATE
