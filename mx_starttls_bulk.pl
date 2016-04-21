#!/usr/bin/env perl
# Copyright 2014 Steffen Ullrich <sullr@cpan.org>
#   This program is free software; you can redistribute it and/or
#   modify it under the same terms as Perl itself.
#
# bulk check for SMTP support and problems
# See -h|--help option for usage

use strict;
use warnings;
use Net::DNS;
use IO::Socket::SSL 1.967;
use IO::Socket::SSL::Utils;
use Data::Dumper;
use Sys::Hostname;
use Time::HiRes 'gettimeofday';
use Getopt::Long qw(:config posix_default bundling);
use Socket;

$|=1;
my $DEBUG = 0;
my $max_task = 500;
my $timeout  = 30;
my $ciphers  = 'DEFAULT';
my $ehlo_domain = hostname() || 'no.such.name.local';
my $ismx = 0;

# multi-line SMTP response, first number of status code in $1
my $smtp_resp = qr{\A(?:\d\d\d-.*\r?\n)*(\d)\d\d .*\r?\n};

my $usage = sub {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<"USAGE";

Bulk analysis of SMTP STARTTLS behavior.
Needs TLS1.2 support in Net::SSLeay/OpenSSL.

Usage: $0 [-d|--debug] [-h|--help] [--max-task N] [--hostname N] [domains]
  -d|--debug      enable debugging
  -h|--help       this help
  --max-task N    maximum number of parallel analysis tasks ($max_task)
  --hostname N    hostname used in EHLO ($ehlo_domain)
  --ciphers C     use OpenSSL cipher string instead of 'DEFAULT'
  --ismx          List of domains is list of MX for domains,
		  i.e. no more MX lookup needed
  domains         List of domains, will read lines from STDIN if not given

The result will contain a line for each given domain with multiple entries
separated by space. The first item will be the domain name. If the second items
starts with '-' it will indicate a failure, like:

  -nomx                No MX for domain found in DNS.
  -nomxip              No IP for MX found in DNS.
  -timeout:...         Timeout of task.
  -smtp-greeting-..    Problem during SMTP greeting.
  -smtp-ehlo-...       Problem during SMTP EHLO command.
  -smtp-starttls-...   Problem during SMTP STARTTLS command.
  -smtp-no-starttls    No STARTTLS support.
  -tls                 TLS handshake finally failed.

Otherwise the second item will indicate the SSL success information like this:

   tls:SSLv23:TLSv1/DHE-RSA-AES256-SHA
         |      |        |
	 |      |        +- cipher used for connection
	 |      +---------- protocol version used for connection
	 +----------------- handshake tried

The following handshakes will be tried in this order until connection success:
   SSLv23      - most compatible handshake
   TLSv1_2     - TLS 1.2 handshake
   TLSv1_1     - TLS 1.1 handshake
   TLSv1       - TLS 1.0 handshake
   SSLv3       - SSL 3.0 handshake
   SSLv23/ALL  - like SSLv23, but offers ALL ciphers (including LOW and ADH)
                 instead of only DEFAULT

The next items give information about handshakes tried and they
succeeded(+tls:...) or failed(-tls:...), e.g.

   +tls:SSLv23:TLSv1/DHE-RSA-AES256-SHA
   -tls:notls10:SSL connect attempt failed...wrong version number

In addition to the handshakes given above the following handshakes will be tried

   notls10 - SSLv23 handshake allowing up to TLS1.0. This will only be tried
             if TLS1.1+ is available. Failure indicate problems for TLS1.0
	     clients.
   no-v3-ciphers - SSLv23 but with explicitly disabling SSL3.0 ciphers. Failure
             indicate broken client, which might tried to work around POODLE
	     related problems by disabling SSL3.0 ciphers (which are needed for
	     TLS1.0 and TLS1.1 too) instead or additionally to disabling SSL3.0
	     protocol version only.  This will only be tried if TLS1.2 is
	     available.
   croak-md5-client-cert - SSLv23 with MD5 client certificates. This might
             trigger a bug in some mail servers which close TLS1.2 connection
	     when they get a MD5 client certificate. Will only be run if TLS1.2
	     is available.

USAGE
};

GetOptions(
    'h|help' => sub { $usage->() },
    'd|debug' => \$DEBUG,
    'max-task=i' => \$max_task,
    'hostname=s' => \$ehlo_domain,
    'ciphers=s' => \$ciphers,
    'ismx' => \$ismx,
) or $usage->();

$usage->("no TLS1.2 support in your Net::SSLeay/OpenSSL")
    if ! defined &Net::SSLeay::CTX_tlsv1_2_new;

my $initial = $ismx ? [ 'A', \&dns_name2a ]:[ 'MX', \&dns_mx ];

my $next_domain = @ARGV ? sub { shift @ARGV } : sub {
    while (1) {
	defined(my $line = <STDIN>) or return;
	return $1 if $line =~m{^([\w\.\-]+)};
    }
};

# What kind of tests we do: [ id,\&run_if_true,%nondefault_ssl_opt ]
my @ssl_tests;
# Start with SSLv23 as the most compatible, then try with downgrades
for(
    qw(SSLv23 TLSv1_2 TLSv1_1 TLSv1),
    defined(&Net::SSLeay::CTX_v3_new) ? ('SSLv3'):()
) {
    push @ssl_tests, [ $_,
	# run only if no success yet
	sub { ! shift->{ssl_success} },
	SSL_version => $_
    ]
}

# If nothing helps try with all ciphers instead of DEFAULT.
push @ssl_tests, [ 'SSLv23/ALL',
    sub { ! shift->{ssl_success} },
    SSL_cipher_list => 'ALL'
];


# Now add some test for some typical problems:
# Wrong POODLE fix by disabling all SSLv3 ciphers. Only relevant if we managed
# to do a TLS1.2 handshake.
push @ssl_tests, [ 'no-v3-ciphers',
    sub {
	my $succ = shift->{ssl_success} or return;
	return $succ->{version} eq 'TLSv1_2';
    },
    SSL_cipher_list => "$ciphers:!TLSv1.2"
];

# Missing support for TLS1.0 clients. Only relevant if we managed to do a
# handshake with TLS1.1+.
push @ssl_tests, [ 'notls10',
    sub {
	my $succ = shift->{ssl_success} or return;
	return $succ->{version} =~ /TLSv1_[12]/;
    },
    SSL_version => 'SSLv23:!TLSv1_2:!TLSv1_1'
];

# *.mail.protection.outlook.com, AntiSpamProxy...
# croak on MD5 client certificate used with TLS1.2
# Do this test only if handshake succeeded with TLS1.2
{
    my $md5cert = create_client_cert('md5',$ehlo_domain);
    push @ssl_tests, [ 'croak-md5-client-cert',
	sub {
	    my $succ = shift->{ssl_success} or return;
	    return $succ->{version} eq 'TLSv1_2';
	},
	SSL_cert        => $md5cert->{cert},
	SSL_key         => $md5cert->{key},
    ],
}


my $res = Net::DNS::Resolver->new;

my (@task,@defer_task);
my $end;
my $done = 0;
while (@task or !$end) {

    # expire old tasks
    my $now = time();
    while (@task && $task[0]{expire} <= $now) {
	print "$task[0]{domain} -timeout:$task[0]{state}\n";  # failed
	$done++;
	shift @task;
    }

    while (@defer_task && @task<$max_task) {
	my $t = shift(@defer_task);
	if ($t->{resume}($t)) {
	    delete $t->{resume};
	    push @task,$t;
	} else {
	    $max_task--;
	    warn "reduce max_task to $max_task\n";
	    $max_task<2 or die "to few parallel tasks!";
	    push @defer_task,$t;
	}
    }

    # read new tasks from stdin
    while (@task<$max_task and !$end) {
	my $dom = &$next_domain or do {
	    $end = 1;
	    last;
	};

	push @task,{
	    domain => $dom,
	    expire => time() + $timeout,
	    wantread => $initial->[1],
	    state => 'dns',
	    ssl_tests => [ @ssl_tests ],
	};
	DEBUG($task[-1],"new task");
	$task[-1]{fd} = $res->bgsend($dom,$initial->[0]) or do {
	    push @defer_task,pop(@task);
	    $defer_task[-1]{resume} = sub {
		my $task = shift;
		$task->{fd} = $res->bgsend($task->{domain},$initial->[0])
		    and return 1;
		warn "failed to create fd for DNS/MX($!)\n";
		0;
	    };
	    last;
	};
    }

    @task or last;
    my $to = $task[0]{expire} - $now;
    my $rmask = my $wmask = '';
    for(@task) {
	vec($rmask,fileno($_->{fd}),1) = 1 if $_->{wantread};
	vec($wmask,fileno($_->{fd}),1) = 1 if $_->{wantwrite};
    }
    $0 = sprintf("scan tasks=%d done=%d defered=%d to=%d",@task+0,$done,@defer_task+0,$to);
    my $rv = select($rmask,$wmask,undef,$to);
    $rv or next;

    for(my $i=0;1;$i++) {
	my $task = $task[$i] or last;
	for([ wantread => $rmask ],[ wantwrite => $wmask ]) {
	    $task->{fd} or last;
	    if (vec($_->[1],fileno($task->{fd}),1)
		and my $sub = delete $task->{$_->[0]}) {
		$sub->($task);
	    }
	}

	if (!$task->{result} && !@{$task->{ssl_tests}}) {
	    # final result
	    my $succ = $task->{ssl_success};
	    $task->{result} = $succ
		? "tls:$succ->{id}:$succ->{version}/$succ->{cipher}"
		: "-tls";
	}

	if ($task->{result}) {
	    my $info = $task->{info} ? " ".join(";",@{$task->{info}}) :"";
	    print "$task->{domain} $task->{result}$info\n";
	    splice(@task,$i,1);
	    $done++;
	    for(@{$task->{related_tasks} || []}) {
		print "$_->{domain} $task->{result}$info\n";
		$done++;
	    }
	    redo;
	} elsif ($task->{resume}) {
	    push @defer_task,$task;
	    splice(@task,$i,1);
	    redo;
	} elsif ($task->{related}) {
	    # not active by its own
	    splice(@task,$i,1);
	    redo;
	}
    }
}

sub dns_mx {
    my $task = shift;
    DEBUG($task,"get mx");
    my $pkt = $res->bgread($task->{fd}) or do {
	$task->{wantread} = \&dns_mx;
	return;
    };
    my @mx =
	map  { $_->exchange }
	sort { $a->preference <=> $b->preference }
	grep { $_->type eq 'MX' }
	$pkt->answer;
    if (!@mx) {
	# check if the given name is instead the MX itself
	$task->{nomx} = 1;
	@mx = $task->{domain};
    }
    my %name2ip  =
	map { $_->type eq 'A' ? ( $_->name,$_->address ):() }
	$pkt->additional;
    my $ip = $name2ip{lc($mx[0])};
    if (!$ip) {
	$task->{wantread} = \&dns_name2a,
	$task->{fd} = $res->bgsend($mx[0],'A');
	if (!$task->{fd}) {
	    $task->{resume} = sub {
		my $task = shift;
		$task->{fd} = $res->bgsend($mx[0],'A') and return 1;
		warn "failed to create fd for DNS/A($!)\n";
		0;
	    };
	}
	return;
    }
    return tcp_connect($task,$ip);
}

sub dns_name2a {
    my $task = shift;
    DEBUG($task,"get addr to mx");
    my $pkt = $res->bgread($task->{fd}) or do {
	$task->{wantread} = \&dns_name2a;
	return;
    };
    my ($ip) = map { $_->type eq 'A' ? ($_->address):() } $pkt->answer;
    if (!$ip) {
	if (delete $task->{nomx}) {
	    DEBUG($task,"no mx found");
	    $task->{result} = '-nomx';
	} else {
	    DEBUG($task,"no addr to mx found");
	    $task->{result} = '-nomxip';
	}
	return;
    }
    DEBUG($task,"assuming name is MX already")
	if delete $task->{nomx};
    return tcp_connect($task,$ip);
}

sub tcp_connect {
    my ($task,$ip) = @_;
    $task->{ip} = $ip;
    $task->{state} = 'tcp';
    # check for other tasks to same IP
    for(@task) {
	if ($_ != $task and $_->{ip} and $_->{ip} eq $ip) {
	    $task->{related} = 1;
	    DEBUG($task,"mark as related to $_->{domain}, ip=$ip");
	    push @{$_->{related_tasks}},$task;
	    return 1;
	}
    }

    DEBUG($task,"start TCP connect to $ip");

    my $fd = $task->{fd} = IO::Socket::INET->new(Proto => 'tcp');
    if(!$fd) {
	warn "failed to create INET socket: $!\n";
	$task->{resume} = sub { return tcp_connect(shift(),$ip) };
	return 0;
    }
    $fd->blocking(0);
    my $saddr = pack_sockaddr_in(25,inet_aton($ip));
    if (connect($fd,$saddr)) {
	# immediate success
	smtp_read_greeting($task);
	1;
    }
    if (! $!{EINPROGRESS} && !$!{EALREADY}) {
	DEBUG($task,"TCP connection to $ip failed($!)");
	$task->{result} = "-tcpconn($!)";
	return 1;
    }
    $task->{saddr} = $saddr;
    $task->{wantwrite} = \&tcp_finish_connect;
    1;
}

sub tcp_finish_connect {
    my $task = shift;
    if (connect($task->{fd},$task->{saddr})) {
	return smtp_read_greeting($task);
    }
    if (! $!{EINPROGRESS} && !$!{EALREADY}) {
	DEBUG($task,"TCP connection to $task->{ip} failed: $!");
	$task->{result} = "-tcpconn($!)";
	return;
    }
    $task->{wantwrite} = \&tcp_finish_connect;
}

sub smtp_read_greeting {
    my $task = shift;
    DEBUG($task,"read SMTP greeting");
    $task->{state} = 'smtp';
    $task->{rbuf} //= '';
    my $n = sysread($task->{fd}, $task->{rbuf}, 4096, length($task->{rbuf}));
    if (!$n) {
	goto again if !defined $n && $!{EWOULDBLOCK};
	DEBUG($task,"got EOF in SMTP greeting");
	$task->{result} = '-smtp-greeting:eof';
	return;
    }
    if ($task->{rbuf} =~s{\A($smtp_resp)}{}) {
	if ($2 != 2) {
	    (my $l = $1) =~s{\r?\n}{<NL>}g;
	    $l =~s{<NL>$}{};
	    DEBUG($task,"got error in SMTP greeting: $l");
	    $task->{result}= "-smtp-greeting:$l";
	} else {
	    $task->{fd}->print("EHLO $ehlo_domain\r\n");
	    $task->{wantread} = \&smtp_read_ehlo;
	}
	return;
    } else {
	goto again;
    }

    again:
    $task->{wantread} = \&smtp_read_greeting;
}

sub smtp_read_ehlo {
    my $task = shift;
    DEBUG($task,"read SMTP ehlo response");
    my $n = sysread($task->{fd}, $task->{rbuf}, 4096, length($task->{rbuf}));
    if (!$n) {
	goto again if !defined $n && $!{EWOULDBLOCK};
	DEBUG($task,"EOF in SMTP ehlo response");
	$task->{result} = '-smtp-ehlo:eof';
	return;
    }
    if ($task->{rbuf} =~s{\A($smtp_resp)}{}) {
	my $l = $1;
	if ($2 != 2) {
	    $l =~s{\r?\n}{<NL>}g;
	    $l =~s{<NL>$}{};
	    DEBUG($task,"error in SMTP ehlo response: $l");
	    $task->{result}= "-smtp-ehlo=$l";
	} elsif ($l =~m{STARTTLS}i) {
	    $task->{fd}->print("STARTTLS\r\n");
	    $task->{wantread} = \&smtp_read_starttls;
	} else {
	    DEBUG($task,"no STARTTLS support");
	    $task->{result} = "-no-starttls";
	}
	return;
    } else {
	goto again;
    }

    again:
    $task->{wantread} = \&smtp_read_ehlo;
}

sub smtp_read_starttls {
    my $task = shift;
    DEBUG($task,"read SMTP starttls response");
    my $n = sysread($task->{fd}, $task->{rbuf}, 4096, length($task->{rbuf}));
    if (!$n) {
	goto again if !defined $n && $!{EWOULDBLOCK};
	DEBUG($task,"EOF in read SMTP starttls response");
	$task->{result} = '-smtp-starttls:eof';
	return;
    }
    if ($task->{rbuf} =~s{\A($smtp_resp)}{}) {
	my $l = $1;
	if ($2 != 2) {
	    $l =~s{\r?\n}{<NL>}g;
	    $l =~s{<NL>$}{};
	    DEBUG($task,"error in read SMTP starttls response: $l");
	    $task->{result}= "-smtp-starttls=$l";
	} else {
	    my (undef,undef,%sslargs) = @{$task->{ssl_tests}[0]};
	    IO::Socket::SSL->start_SSL($task->{fd},
		SSL_version => 'SSLv23',
		SSL_cipher_list => $ciphers,
		%sslargs,
		SSL_verify_mode => 0,
		SSL_startHandshake => 0,
	    ) or die $SSL_ERROR;
	    return ssl_connect($task);
	}
	return;
    } else {
	goto again;
    }

    again:
    $task->{wantread} = \&smtp_read_starttls;
}

sub ssl_connect {
    my $task = shift;
    $task->{state} = 'tls';
    my $ssl_tests = $task->{ssl_tests};
    my ($id,undef,%sslargs) = @{$ssl_tests->[0]};
    my $result;
    if ($task->{fd}->connect_SSL) {
	my $version = $task->{fd}->get_sslversion;
	my $cipher  = $task->{fd}->get_cipher;
	DEBUG($task,"success in TLS connect $id");
	$result = "+tls:$id:$version/$cipher";
	$task->{ssl_success} ||= {
	    id => $id,
	    version => $version,
	    cipher  => $cipher,
	};
    } elsif ($!{EWOULDBLOCK}) {
	if ($SSL_ERROR == SSL_WANT_READ) {
	    DEBUG($task,"want read in TLS connect $id");
	    $task->{wantread} = \&ssl_connect;
	    return;
	} elsif ($SSL_ERROR == SSL_WANT_WRITE) {
	    DEBUG($task,"want write in TLS connect $id");
	    $task->{wantwrite} = \&ssl_connect;
	    return;
	}
    }
    if (!$result) {
	DEBUG($task,"error in TLS connect $id: $SSL_ERROR");
	return _next_ssl_test($task,"-tls:$SSL_ERROR");
    }
    $task->{fd}->print("EHLO $ehlo_domain\r\n");
    $task->{wantread} = \&ssl_read_ehlo;
}

sub ssl_read_ehlo {
    my $task = shift;
    DEBUG($task,"read SMTP ehlo response after STARTTLS");
    my $n = sysread($task->{fd}, $task->{rbuf}, 16384, length($task->{rbuf}));
    if (!defined $n) {
	if ($!{EWOULDBLOCK}) {
	    if ($SSL_ERROR == SSL_WANT_READ) {
		DEBUG($task,"want read in TLS ehlo");
		$task->{wantread} = \&ssl_read_ehlo,
		return;
	    } elsif ($SSL_ERROR == SSL_WANT_WRITE) {
		DEBUG($task,"want write in TLS ehlo");
		$task->{wantwrite} = \&ssl_read_ehlo,
		return;
	    }
	}
	DEBUG($task,"error in TLS ehlo: $SSL_ERROR");
	$task->{result}= "-tls:ehlo:$SSL_ERROR";
	return;
    }
    if (!$n) {
	DEBUG($task,"EOF in SMTP ehlo response after starttls");
	$task->{result} = '-tls:ehlo-eof';
	return;
    }
    if ($task->{rbuf} =~s{\A($smtp_resp)}{}) {
	my $l = $1;
	if ($2 != 2) {
	    $l =~s{\r?\n}{<NL>}g;
	    $l =~s{<NL>$}{};
	    DEBUG($task,"error in TLS ehlo response: $l");
	    return _next_ssl_test($task,"-tls:ehlo=$l");
	} else {
	    DEBUG($task,"success in TLS ehlo response");
	    return _next_ssl_test($task,"+tls:".$task->{fd}->get_sslversion."/".$task->{fd}->get_cipher);
	}
    }
    # need more
    DEBUG($task,"TLS ehlo response - need more data");
    $task->{wantread} = \&ssl_read_ehlo,
}

sub _next_ssl_test {
    my ($task,$result) = @_;

    # done with this test
    my $ssl_tests = $task->{ssl_tests};
    my ($id) = @{ $ssl_tests->[0] };
    $result =~s{^(.tls:)}{$1$id:} or die $result;
    push @{$task->{info}}, $result;
    shift(@$ssl_tests);

    # find next test
    while (@$ssl_tests) {
	my ($id,$runif) = @{ $ssl_tests->[0] };
	if ($runif->($task)) {
	    #warn "next test: $id\n";
	    last;
	} else {
	    #warn "skip test: $id\n";
	    shift(@$ssl_tests);
	}
    }

    if(@$ssl_tests) {
	# non-final, do next test
	$task->{expire} = time() + $timeout;
	return tcp_connect($task,$task->{ip});
    }
}



# create self-signed client certificate
sub create_client_cert {
    my $digest = shift || 'sha256';
    my $name   = shift || 'ssl.test';
    my ($cert,$key) = CERT_create(
	digest => $digest,
	CA => 1,
	subject => { CN => $name },
	ext => [
	    {
		sn => 'keyUsage',
		data => 'critical,digitalSignature,keyEncipherment,keyCertSign'
	    },
	    {
		sn => 'extendedKeyUsage',
		data => 'serverAuth,clientAuth',
	    }
	]
    );
    return { cert => $cert, key => $key };
}

sub DEBUG {
    $DEBUG or return;
    my $task = shift;
    my $msg = @_>1 ? shift : '%s';
    printf STDERR "DEBUG %.3f %s $msg\n",0+gettimeofday(),$task->{domain},@_;
}
