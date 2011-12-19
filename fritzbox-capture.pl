#!/usr/bin/perl

use strict;
use warnings;
use WWW::Mechanize;
use Digest::MD5 'md5_hex';
use Getopt::Long qw(:config posix_default bundling);


my $base = 'http://fritz.box';
my $DEBUG = 0;
my $verbose = 0;
GetOptions(
    'url=s'   => \$base,
    'h|help'  => sub { usage() },
    'd|debug' => \$DEBUG,
    'v|verbose' => \$verbose,
);

sub usage {
    print STDERR <<USAGE;

Starts/stops traffic capture from fritz.box on the external summary
interface. Capture data are in pcap format and are written to stdout, while
they get received.

The password for fritz.box is read w/o prompt from stdin, to use with
$0 < protected_password_file

Usage: $0 [options] [mode]
Mode is either start or stop, defaults to stop. Usually fritz.box stops
capturing if the receiver closes the tcp connection, so stop is not
necessary in most cases.
Options:
    -h|--help     this help
    -v|--verbose  update STDERR with number of downloaded bytes
    -d|--debug    print debugging info
    --url URL     use base url of URL, instead of $base
USAGE
    exit(2);
}

debug("reading password");
chomp( my $pw = <STDIN> );
my $start = ( $ARGV[0] || 'stop' ) =~m/start/i;
my $selector = $start ? '#uiStart_0' : '#uiStop_0';

my $mech = WWW::Mechanize->new();

# login
debug("getting login page");
$mech->get("$base/login.lua");
my $ct = $mech->content;
my ($challenge) = $ct =~m{var challenge = "([[:xdigit:]]+)"}
    or die "no challenge found";

debug("challenge is $challenge, sending response");
my $uiResp = "$challenge-". md5_hex(
    join('',map { "$_\0" } split(//,"$challenge-$pw")));
$mech->post( "$base/login.lua" , {
    response => $uiResp,
    get_page => '/capture.lua',
});

my $form = $mech->form_id('uiMainForm') 
    or die "no form uiMainForm";
debug("got capture form, choosing $selector");
my $req = $form->click($selector);
if ( $start ) {
    $|=1;
    $mech->add_handler(
	response_header => sub {
	    my $resp = shift;
	    debug("response was:\n".$resp->as_string);
	}
    );
    my $bytes = 0;
    $mech->request($req,
	sub { 
	    my $buf = shift; 
	    if ($bytes<24) {
		# replace pcap type 14 with DLT_RAW, byte 20 \x0e -> \x0c
		my $i = 20 - $bytes;
		if ( length($buf)>=$i+1 and substr($buf,$i,1) eq "\x0e" ) {
		    substr($buf,$i,1,"\x0c");
		    debug("replaced pcap type with DLT_RAW");
		}
	    }
	    $bytes += length($buf);
	    print STDERR "\r$bytes   \r" if $verbose and -t STDERR;
	    print $buf; 
	},
	8192,
    );
} else {    
    $mech->request($req);
    die $mech->content;
}
    

sub debug {
    $DEBUG or return;
    my $msg = shift;
    $msg = sprintf($msg,@_) if @_;
    print STDERR $msg,"\n";
}


__END__


=head1 NAME

fritzbox-capture - use traffic capture feature of router Fritz!Box per cmdline

=head1 DESCRIPTION

The router Fritz!Box has a hidden feature to let it capture traffic in pcap
format, which then can be processed with wireshark, tcpdump or similar tools.

This scripts lets you start a capture.
Stopping is also possible, but usually the capture stops automatically if the
downloading connection to Fritz!Box is closed.

The script sends the pcap data nearly unchanged to stdout, the only change is to
fix the pcap type to DLT_RAW, so that tcpdump can read the files.

=head1 PREREQUISITES

Needs L<WWW::Mechanize>.

=head1 BUGS

Works against Fritz!Box 7240 with firmware 73.05.05.
Might not work against other hardware or firmware.

=head1 AUTHOR

Copyright Steffen Ullrich 2011

=pod SCRIPT CATEGORIES

Networking

