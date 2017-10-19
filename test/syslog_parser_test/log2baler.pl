#!/usr/bin/env perl
# This will just send the text from the file as-is.
use strict;
use warnings;
use Socket;
use Pod::Usage;
use Getopt::Long;

my $host = "localhost"; # default
my $port = "55555"; # default
my $help;

GetOptions(
	"host=s" => \$host,
	"port=i" => \$port,
	"help" => \$help
);

pod2usage(1) if $help;

my $addr = inet_aton($host);
my $paddr = sockaddr_in($port, $addr);

my $proto = getprotobyname("tcp");

socket(SOCK, PF_INET, SOCK_STREAM, $proto) || die "socket: $!";
connect(SOCK, $paddr) || die "connect: $!";

my $line = <STDIN>;
chomp $line;

die "Empty input ..." if (!$line);

do {
	chomp $line;
	print SOCK "$line\n";
} while ($line = <STDIN>);

close(SOCK);

__END__

=head1 NAME

syslog2baler.pl - Pipe syslog (STDIN) to baler daemon for processing.

=head1 SYNOPSIS

syslog2baler.pl [options] < logfile

 Options:
	-host	The hostname of where balerd reside. (default: localhost)
	-port	The port number that balrrd listened to. (default: 55555)
	-help	Show this help message.
