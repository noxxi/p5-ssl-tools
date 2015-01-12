#!/usr/bin/perl
#
# Copyright 2013..2015 Steffen Ullrich <sullr@cpan.org>
#   This program is free software; you can redistribute it and/or
#   modify it under the same terms as Perl itself.

use strict;
use warnings;
use Socket;
use IO::Socket::SSL 1.984;
use IO::Socket::SSL::Utils;
use Getopt::Long qw(:config posix_default bundling);
use Data::Dumper;


my $can_ocsp = IO::Socket::SSL->can_ocsp;
my $ocsp_cache = $can_ocsp && IO::Socket::SSL::OCSP_Cache->new;

my %starttls = (
    ''  => [ 443,undef, 'http' ],
    'smtp' => [ 25, \&smtp_starttls, 'smtp' ],
    'http_proxy' => [ 443, \&http_connect,'http' ],
    'http_upgrade' => [ 80, \&http_upgrade,'http' ],
    'imap' => [ 143, \&imap_starttls,'imap' ],
    'pop'  => [ 110, \&pop_stls,'pop3' ],
    'ftp'  => [ 21, \&ftp_auth,'ftp' ],
    'postgresql'  => [ 5432, \&postgresql_init,'default' ],
);

my $verbose = 0;
my $timeout = 10;
my ($stls,$stls_arg);
my $capath;
my $all_ciphers;
my $show_chain;
my $dump_chain;
my %conf;
my $max_cipher = 'HIGH:ALL';
GetOptions(
    'h|help' => sub { usage() },
    'v|verbose:1' => \$verbose,
    'd|debug:1' => \$IO::Socket::SSL::DEBUG,
    'T|timeout=i' => \$timeout,
    'CApath=s' => \$capath,
    'show-chain' => \$show_chain,
    'dump-chain' => \$dump_chain,
    'all-ciphers' => \$all_ciphers,
    'starttls=s' => sub {
	($stls,$stls_arg) = $_[1] =~m{^(\w+)(?::(.*))?$};
	usage("invalid starttls $stls") if ! $starttls{$stls};
    },
    'cert=s' => \$conf{SSL_cert_file},
    'key=s'  => \$conf{SSL_key_file},
    'name=s' => \$conf{SSL_hostname},
    'max-cipher=s' => \$max_cipher,
) or usage("bad usage");
@ARGV or usage("no hosts given");
my %default_ca =
    ! $capath ? () :
    -d $capath ? ( SSL_ca_path => $capath, SSL_ca_file => '' ) :
    -f $capath ? ( SSL_ca_file => $capath, SSL_ca_path => '' ) :
    die "no such file or dir: $capath";
my $peer_certificates = IO::Socket::SSL->can('peer_certificates')
    || sub {};

$conf{SSL_verifycn_name} ||= $conf{SSL_hostname} if $conf{SSL_hostname};
if ($conf{SSL_cert_file}) {
    $conf{SSL_key_file} ||= $conf{SSL_cert_file};
    $conf{SSL_use_cert} = 1;
}


sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<USAGE;

Analyze SSL connectivity for problems.
Usage: $0 [options] (host|host:port)+
Options:
  -h|--help              - this screen
  -d|--debug level       - IO::Socket::SSL/Net::SSLeay debugging

  # how to connect
  --starttls proto[:arg] - start plain and upgrade to SSL with starttls protocol
			   (imap,smtp,http_upgrade,http_proxy,pop,ftp,postgresql)
  -T|--timeout T         - use timeout (default 10)

  # SSL specific settings
  --CApath file|dir      - use given dir|file instead of system default CA store
  --cert cert            - use given certificate for client authentication
  --key  key             - use given key for client authentication (default: cert)
  --name name            - use given name as server name in verification and SNI
			   instead of host (useful if target is given as IP)
  --max-cipher set       - maximum cipher set to try, default HIGH:ALL.
			   Some servers or middleboxes have problems with this set
			   so it can be reduced.

  # what to show
  -v|--verbose level     - verbose output
  --all-ciphers          - find out all supported ciphers
  --show-chain           - show certificate chain
  --dump_chain           - dump certificate chain, e.g. all certificates as PEM

Examples:

  $0 --show-chain --all-ciphers -v3 www.live.com:443
  $0 --starttls http_proxy:proxy_host:proxy_port www.live.com:443
  $0 --starttls imap mail.gmx.de

USAGE
    exit(2);
}



my @tests;
for my $host (@ARGV) {
    my ($ip,$port);
    $host =~m{^(?:\[(\w\.\-\:+)\]|([\w\.\-]+)):(\w+)$|^([\w\.\-:]+)$}
	or die "invalid dst: $host";
    $host = $1||$2||$4;
    my $st = $starttls{$stls ||''};
    $port = $3 || $st->[0] || 443;
    if ( $host =~m{:|^[\d\.]+$} ) {
	$ip = $host;
	$host = undef;
    }
    push @tests, [ $host||$ip,$port,$conf{SSL_hostname}||$host,$st->[1],$st->[2] || 'default' ];
}


my $ioclass = IO::Socket::SSL->can_ipv6 || 'IO::Socket::INET';
for my $test (@tests) {
    my ($host,$port,$name,$stls_sub,$scheme) = @$test;
    VERBOSE(1,"checking host=$host port=$port".
	($stls ? " starttls=$stls":""));

    my $tcp_connect = sub {
	my $tries = shift || 1;
	my ($cl,$error);
	my %ioargs = (
	    PeerAddr => $host,
	    PeerPort => $port,
	    Timeout => $timeout,
	);
	for(1..$tries) {
	    if ($stls_sub) {
		last if $cl = eval { $stls_sub->(\%ioargs,$stls_arg) };
		$error = $@ || 'starttls error';
		$cl = undef;
	    } elsif ( $cl = $ioclass->new(%ioargs)) {
		last;
	    } else {
		$error = "tcp connect: $!";
	    }
	}
	$cl or die $error;
    };

    my @handshakes;
    my @problems;

    # basic connects without verification or any TLS extensions (OCSP)
    # find out usable version and ciphers. Because some hosts (like cloudflare)
    # behave differently if SNI is used we try to use it and only fall back if
    # it fails.
    my ($version,$cipher,$good_conf);
    my $sni = $name;
    my $try_sslversion = sub {
	my $v = shift;
	my (@protocols,@err);
	for my $ciphers ( '',$max_cipher ) {
	    my $cl = &$tcp_connect;
	    if ( IO::Socket::SSL->start_SSL($cl,
		%conf,
		SSL_version => $v,
		SSL_verify_mode => 0,
		SSL_hostname => $sni,
		SSL_cipher_list => $ciphers,
	    )) {
		$version = $cl->get_sslversion();
		$cipher = $cl->get_cipher();
		if (!@protocols) {
		    push @protocols, ($version, $cipher);
		} elsif ($protocols[-1] ne $cipher) {
		    push @protocols, $cipher;
		}
		$good_conf ||= { 
		    %conf, 
		    SSL_version => $v, 
		    SSL_hostname => $sni, 
		    SSL_cipher_list => $ciphers 
		};
		VERBOSE(2,"version $v no verification, ciphers=$ciphers -> $version,$cipher");
	    } else {
		VERBOSE(2,"version $v, no verification, ciphers=$ciphers -> FAIL! $SSL_ERROR");
		push @err, $SSL_ERROR if ! @err || $err[-1] ne $SSL_ERROR;
	    }
	}
	return (\@protocols,\@err);
    };

    my $use_version;
    my $best_version;
    TRY_PROTOCOLS:
    for(
	# most compatible handshake - should better be supported by all
	'SSLv23',
	# version specific handshakes - some hosts fail instead of downgrading
	defined &Net::SSLeay::CTX_tlsv1_2_new ? ('TLSv1_2'):(),
	defined &Net::SSLeay::CTX_tlsv1_1_new ? ('TLSv1_1'):(),
	defined &Net::SSLeay::CTX_tlsv1_new   ? ('TLSv1')  :(),
	defined &Net::SSLeay::CTX_v3_new      ? ('SSLv3')  :(),
    ) {
	my ($protocols,$err) = $try_sslversion->($_);
	if (@$protocols) {
	    $use_version ||= $_;
	    $best_version ||= $protocols->[0];
	    push @handshakes, [ $_, @$protocols ];
	} else {
	    push @handshakes, [ $_,\"@$err" ];
	}
    }

    if ($best_version) {
	VERBOSE(1,"successful connect with $best_version, cipher=$cipher, sni=$sni and no other TLS extensions");
    } elsif ($sni) {
	$sni = '';
	# retry without SNI
	goto TRY_PROTOCOLS;
    } else {
	die "$host failed basic SSL connect: $SSL_ERROR\n";
    }

    my $sni_status;
    if (!$sni) {
	if ($version =~m{^TLS}) {
	    VERBOSE(1,"SNI FAIL!");
	    push @problems, "using SNI (default)";
	    $sni_status = 'FAIL';
	}
    } else {
	VERBOSE(1,"SNI success");
	$sni_status = 'ok';
    }


    # get chain info
    my (@cert_chain,@cert_chain_nosni);
    if ($show_chain || $dump_chain) {
	for(
	    [ $good_conf, \@cert_chain ],
	    ! $good_conf->{SSL_hostname} ? ()
		# cloudflare has different cipher list without SNI, so don't
		# enforce the existing one
		: ([ { %$good_conf, SSL_cipher_list => undef, SSL_hostname => '' }, \@cert_chain_nosni ])
	) {
	    my ($conf,$chain) = @$_;
	    my $cl = &$tcp_connect;
	    my %verify_chain;
	    if ( IO::Socket::SSL->start_SSL($cl, %$good_conf,
		SSL_verify_callback => sub {
		    my ($valid,$store,$str,$err,$cert,$depth) = @_;
		    # Since this only a temporary reference we should convert it
		    # directly to PEM.

		    my ($subject,$bits);
		    $subject = Net::SSLeay::X509_NAME_oneline(
			Net::SSLeay::X509_get_subject_name($cert));
		    if (!$depth) {
			my @san = $cl->peer_certificate('subjectAltNames');
			for( my $i=0;$i<@san;$i++) {
			    $san[$i] = 'DNS' if $san[$i] == 2;
			    $san[$i] .= ":".splice(@san,$i+1,1);
			}
			$subject .= " SAN=".join(",",@san) if @san;
		    }
		    if (my $pkey = Net::SSLeay::X509_get_pubkey($cert)) {
			$bits = eval { Net::SSLeay::EVP_PKEY_bits($pkey) };
			Net::SSLeay::EVP_PKEY_free($pkey);
		    }
		    my $pem = PEM_cert2string($cert);
		    $verify_chain{$pem} = [
			$bits||'???',
			$subject,
			join('|', grep { $_ } @{ CERT_asHash($cert)->{ocsp_uri} || []}),
			$pem,
			$depth,
			'-'
		    ];
		    return 1;
		},
	    )) {
		for my $cert ( $peer_certificates->($cl) ) {
		    my ($subject,$bits);
		    $subject = Net::SSLeay::X509_NAME_oneline(
			Net::SSLeay::X509_get_subject_name($cert));
		    if ( !@$chain) {
			my @san = $cl->peer_certificate('subjectAltNames');
			for( my $i=0;$i<@san;$i++) {
			    $san[$i] = 'DNS' if $san[$i] == 2;
			    $san[$i] .= ":".splice(@san,$i+1,1);
			}
			$subject .= " SAN=".join(",",@san) if @san;
		    }
		    if (my $pkey = Net::SSLeay::X509_get_pubkey($cert)) {
			$bits = eval { Net::SSLeay::EVP_PKEY_bits($pkey) };
			Net::SSLeay::EVP_PKEY_free($pkey);
		    }
		    my $pem = PEM_cert2string($cert);
		    my $vc = delete $verify_chain{$pem};
		    if (!$vc) {
			push @problems, "server sent unused chain certificate ".
			    "'$subject'";
		    }
		    push @$chain,[
			$bits||'???',
			$subject,
			join('|', grep { $_ } @{ CERT_asHash($cert)->{ocsp_uri} || []}),
			$pem,
			$vc ? $vc->[4] : '-', # depth
			$#$chain+1,
		    ],
		}
		for (sort { $a->[4] <=> $b->[4] } values %verify_chain) {
		    push @$chain,$_;
		}
	    } else {
		die "failed to connect with previously successful config: $SSL_ERROR";
	    }
	}
	# if same certificate ignore nosni
	if (@cert_chain_nosni
	    && $cert_chain_nosni[0][3] eq $cert_chain[0][3]) {
	    VERBOSE(2,"same certificate in without SNI");
	    @cert_chain_nosni = ();
	}
    }

    # check verification against given/builtin CA w/o OCSP
    my $verify_status;
    my $cl = &$tcp_connect;
    if ( IO::Socket::SSL->start_SSL($cl, %$good_conf,
	SSL_verify_mode => SSL_VERIFY_PEER,
	SSL_ocsp_mode => SSL_OCSP_NO_STAPLE,
	SSL_verifycn_scheme => 'none',
	%default_ca
    )) {
	%conf = ( %$good_conf, SSL_verify_mode => SSL_VERIFY_PEER, %default_ca );
	if (!$cl->peer_certificate) {
	    VERBOSE(1,"no peer certificate (anonymous authentication)");
	    %conf = %$good_conf;
	    $verify_status = 'anon';
	} elsif ( $cl->verify_hostname( $name,$scheme )) {
	    VERBOSE(1,"certificate verify success");
	    $verify_status = 'ok';
	    %conf = %$good_conf = ( %conf,
		SSL_verifycn_scheme => $scheme,
		SSL_verifycn_name => $name,
	    );
	} else {
	    my @san = $cl->peer_certificate('subjectAltNames');
	    for( my $i=0;$i<@san;$i++) {
		$san[$i] = 'DNS' if $san[$i] == 2;
		$san[$i] .= ":".splice(@san,$i+1,1);
	    }
	    VERBOSE(1,"certificate verify - name does not match:".
		" subject=".$cl->peer_certificate('subject').
		" SAN=".join(",",@san)
	    );
	    $verify_status = 'name-mismatch';
	    %conf = %$good_conf = ( %conf, SSL_verifycn_scheme => 'none');
	}

    } else {
	VERBOSE(1,"certificate verify FAIL!");
	$verify_status = "FAIL: $SSL_ERROR";
	push @problems, "using certificate verification (default) -> $SSL_ERROR";
    }

    # check with OCSP stapling
    my $ocsp_staple;
    if ( $can_ocsp && $verify_status eq 'ok' ) {
	my $cl = &$tcp_connect;
	$conf{SSL_ocsp_cache} = $ocsp_cache;
	if ( IO::Socket::SSL->start_SSL($cl, %conf)) {
	    if ( ${*$cl}{_SSL_ocsp_verify} ) {
		$ocsp_staple = 'got stapled response',
	    } else {
		$ocsp_staple = 'no stapled response',
	    }
	    VERBOSE(1,"OCSP stapling: $ocsp_staple");
	} else {
	    $ocsp_staple = "FAIL: $SSL_ERROR";
	    $conf{SSL_ocsp_mode} = SSL_OCSP_NO_STAPLE;
	    VERBOSE(1,"access with OCSP stapling FAIL!");
	    push @problems, "using OCSP stapling (default) -> $SSL_ERROR";
	}
    }

    my $ocsp_status;
    if ( $can_ocsp && $verify_status eq 'ok' ) {
	my $cl = &$tcp_connect;
	$conf{SSL_ocsp_mode} |= SSL_OCSP_FULL_CHAIN;
	if ( ! IO::Socket::SSL->start_SSL($cl, %conf)) {
	    die sprintf("failed with SSL_ocsp_mode=%b, even though it succeeded with default mode",
		$conf{SSL_ocsp_mode});
	}
	my $ocsp_resolver = $cl->ocsp_resolver;
	my %todo = $ocsp_resolver->requests;
	while (my ($uri,$req) = each %todo) {
	    VERBOSE(3,"need to send %d bytes OCSP request to %s",length($req),$uri);
	}
	my $errors = $ocsp_resolver->resolve_blocking();
	die "resolver not finished " if ! defined $errors;
	if ( ! $errors ) {
	    VERBOSE(1,"all certificates verified");
	    $ocsp_status = "good";
	} else {
	    VERBOSE(1,"failed to verify certicates: $errors");
	    $ocsp_status = "FAIL: $errors";
	}
	if (my $soft_error = $ocsp_resolver->soft_error) {
	    $ocsp_status .= " (soft error: $soft_error)"
	}
    }

    # check out all supported ciphers
    my @ciphers;
    {
	my $c = "$max_cipher:eNULL";
	while ($all_ciphers || @ciphers<2 ) {
	    my $cl = &$tcp_connect;
	    if ( IO::Socket::SSL->start_SSL($cl,
		%conf,
		SSL_verify_mode => 0,
		SSL_version => $conf{SSL_version},
		SSL_cipher_list => $c,
	    )) {
		push @ciphers, [ $cl->get_sslversion, $cl->get_cipher ];
		$c .= ":!".$ciphers[-1][1];
		VERBOSE(2,"connect with version %s cipher %s",
		    @{$ciphers[-1]});
	    } else {
		VERBOSE(3,"handshake failed with $c: $SSL_ERROR");
		last;
	    }
	}
    }

    # try to detect if the server accepts our cipher order by trying two
    # ciphers in different order
    my $server_cipher_order;
    if (@ciphers>=2) {
	my %used_cipher;
	for( "$ciphers[0][1]:$ciphers[1][1]","$ciphers[1][1]:$ciphers[0][1]" ) {
	    my $cl = &$tcp_connect;
	    if ( IO::Socket::SSL->start_SSL($cl,
		%conf,
		SSL_version => $use_version,
		SSL_verify_mode => 0,
		SSL_hostname => '',
		SSL_cipher_list => $_,
	    )) {
		$used_cipher{$cl->get_cipher}++;
	    } else {
		warn "failed to SSL handshake with SSL_cipher_list=$_: $SSL_ERROR";
	    }
	}
	if (keys(%used_cipher) == 2) {
	    VERBOSE(2,"client decides cipher order");
	    $server_cipher_order = 0;
	} elsif ( (values(%used_cipher))[0] == 2 ) {
	    VERBOSE(2,"server decides cipher order");
	    $server_cipher_order = 1;
	}
    }


    # summary
    print "-- $host port $port".($stls? " starttls $stls":"")."\n";
    print " ! $_\n" for(@problems);
    print " * maximum SSL version  : $best_version ($use_version)\n";
    print " * supported SSL versions with handshake used and preferred cipher(s):\n";
    printf "   * %-9s %-9s %s\n",qw(handshake protocols ciphers);
    for(@handshakes) {
	printf("   * %-9s %-9s %s\n",
	    $_->[0],
	    ref($_->[1])
		? ("FAILED: ${$_->[1]}","")
		: ($_->[1], join(" ",@{$_}[2..$#$_]))
	);
    }
    print " * cipher order by      : ".(
	! defined $server_cipher_order ? "unknown\n" :
	$server_cipher_order ? "server\n" : "client\n"
    );
    print " * SNI supported        : $sni_status\n" if $sni_status;
    print " * certificate verified : $verify_status\n";
    if ($show_chain) {
	for(my $i=0;$i<@cert_chain;$i++) {
	    my $c = $cert_chain[$i];
	    print "   * [$c->[5]/$c->[4]] bits=$c->[0], ocsp_uri=$c->[2], $c->[1]\n"
	}
	if (@cert_chain_nosni) {
	    print " * chain without SNI\n";
	    for(my $i=0;$i<@cert_chain_nosni;$i++) {
		my $c = $cert_chain_nosni[$i];
		print "   * [$c->[5]/$c->[4]] bits=$c->[0], ocsp_uri=$c->[2], $c->[1]\n"
	    }
	}
    }
    print " * OCSP stapling        : $ocsp_staple\n" if $ocsp_staple;
    print " * OCSP status          : $ocsp_status\n" if $ocsp_status;
    if ($all_ciphers) {
	print " * supported ciphers with $use_version handshake\n";
	for(@ciphers) {
	    printf "   * %6s %s\n",@$_;
	}
    }
    if ($dump_chain) {
	print "---------------------------------------------------------------\n";
	for(my $i=0;$i<@cert_chain;$i++) {
	    my $c = $cert_chain[$i];
	    print "# $c->[1]\n$c->[3]\n";
	}
    }
}



sub smtp_starttls {
    my $cl = $ioclass->new(%{shift()}) or die "tcp connect: $!";
    my $last_status_line = qr/((\d)\d\d(?:\s.*)?)/;
    my ($line,$code) = _readlines($cl,$last_status_line);
    $code == 2 or die "server denies access: $line\n";
    print $cl "EHLO example.com\r\n";
    ($line,$code) = _readlines($cl,$last_status_line);
    $code == 2 or die "server did not accept EHLO: $line\n";
    print $cl "STARTTLS\r\n";
    ($line,$code) = _readlines($cl,$last_status_line);
    $code == 2 or die "server did not accept STARTTLS: $line\n";
    VERBOSE(3,"...reply to starttls: $line");
    return $cl;
}

sub imap_starttls {
    my $cl = $ioclass->new(%{shift()}) or die "tcp connect: $!";
    <$cl>; # welcome
    print $cl "abc STARTTLS\r\n";
    while (<$cl>) {
	m{^abc (OK)?} or next;
	$1 or die "STARTTLS failed: $_";
	s{\r?\n$}{};
	VERBOSE(3,"...starttls: $_");
	return $cl;
    }
    die "starttls failed";
}

sub pop_stls {
    my $cl = $ioclass->new(%{shift()}) or die "tcp connect: $!";
    <$cl>; # welcome
    print $cl "STLS\r\n";
    my $reply = <$cl>;
    die "STLS failed: $reply" if $reply !~m{^\+OK};
    $reply =~s{\r?\n}{};
    VERBOSE(3,"...stls $reply");
    return $cl;
}

sub http_connect {
    my ($ioargs,$proxy) = @_;
    $proxy or die "no proxy host:port given";
    $proxy =~m{^(?:\[(.+)\]|([^:]+)):(\w+)$} or die "invalid dst: $proxy";
    my $cl = $ioclass->new( %$ioargs,
	PeerAddr => $1||$2,
	PeerPort => $3,
    ) or die "tcp connect: $!";
    print $cl "CONNECT $ioargs->{PeerAddr}:$ioargs->{PeerPort} HTTP/1.0\r\n\r\n";
    my $hdr = _readlines($cl,qr/\r?\n/);
    $hdr =~m{\A(HTTP/1\.[01]\s+(\d\d\d)[^\r\n]*)};
    die "CONNECT failed: $1" if $2 != 200;
    VERBOSE(3,"...connect request: $1");
    return $cl;
}

sub http_upgrade {
    my ($ioargs,$arg) = @_;
    my $hostname = $ioargs->{PeerAddr};
    my $cl = $ioclass->new(%$ioargs) or die "tcp connect: $!";
    my $rq;
    if ( $arg && $arg =~m{^get(?:=(\S+))?}i ) {
	my $path = $1 || '/';
	$rq = "GET $path HTTP/1.1\r\n".
	    "Host: $hostname\r\n".
	    "Upgrade: TLS/1.0\r\n".
	    "Connection: Upgrade\r\n".
	    "\r\n";
    } else {
	my $path = $arg && $arg =~m{^options=(\S+)}i
	    ? $1:'*';
	$rq = "OPTIONS $path HTTP/1.1\r\n".
	    "Host: $hostname\r\n".
	    "Upgrade: TLS/1.0\r\n".
	    "Connection: Upgrade\r\n".
	    "\r\n";
    }
    print $cl $rq;
    my $hdr = _readlines($cl,qr/\r?\n/);
    $hdr =~m{\A(HTTP/1\.[01]\s+(\d\d\d)[^\r\n]*)};
    die "upgrade not accepted, code=$2 (expect 101): $1" if $2 != 101;
    VERBOSE(3,"...tls upgrade request: $1");
    return $cl;
}

sub ftp_auth {
    my $cl = $ioclass->new(%{shift()}) or die "tcp connect: $!";
    my $last_status_line = qr/((\d)\d\d(?:\s.*)?)/;
    my ($line,$code) = _readlines($cl,$last_status_line);
    die "server denies access: $line\n" if $code != 2;
    print $cl "AUTH TLS\r\n";
    ($line,$code) = _readlines($cl,$last_status_line);
    die "AUTH TLS denied: $line\n" if $code != 2;
    VERBOSE(3,"...ftp auth: $line");
    return $cl;
}

sub postgresql_init {
    my $cl = $ioclass->new(%{shift()}) or die "tcp connect: $!";
    # magic header to initiate SSL:
    # http://www.postgresql.org/docs/devel/static/protocol-message-formats.html
    print $cl pack("NN",8,80877103);
    read($cl, my $buf,1 ) or die "did not get response from postgresql";
    $buf eq 'S' or die "postgresql does not support SSL (response=$buf)";
    VERBOSE(3,"...postgresql supports SSL: $buf");
    return $cl;
}

sub _readlines {
    my ($cl,$stoprx) = @_;
    my $buf = '';
    while (<$cl>) {
	$buf .= $_;
	return $buf if ! $stoprx;
	next if ! m{\A$stoprx\Z};
	return ( m{\A$stoprx\Z},$buf );
    }
    die "eof" if $buf eq '';
    die "unexpected response: $buf";
}



sub VERBOSE {
    my $level = shift;
    $verbose>=$level || return;
    my $msg = shift;
    $msg = sprintf($msg,@_) if @_;
    my $prefix = $level == 1 ? '+ ' : $level == 2 ? '* ' : "<$level> ";
    print STDERR "$prefix$msg\n";
}
