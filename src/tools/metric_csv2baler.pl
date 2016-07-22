#!/usr/bin/env perl
use strict;
use warnings;
use Socket;
use Pod::Usage;
use Getopt::Long;

my $host = "localhost";
my $port = 30003;
my $stdout;
my $help;

GetOptions(
	"host=s" => \$host,
	"port=i" => \$port,
	"stdout" => \$stdout,
	"help" => \$help
);

pod2usage(1) if $help;

my $addr = inet_aton($host);
my $paddr = sockaddr_in($port, $addr);
my $proto = getprotobyname("tcp");

unless ($stdout) {
	socket(SOCK, PF_INET, SOCK_STREAM, $proto) || die "socket: $!";
	connect(SOCK, $paddr) || die "connect: $!";
}

# Expecting metric names from the first line

my $line = <STDIN>;
chomp $line;
my @mname = split /,/, $line;

for (my $i = 2; $i < scalar @mname; $i++) {
	$mname[$i] =~ s/^\s+|\s+$//g;
}

while (my $line = <STDIN>) {
	chomp $line;
	my @values = split /,/, $line;
	my $sec = $values[0];
	my $producer = $values[2];
	my $comp_id = $values[3];
	my $job_id = $values[4];
	if ($stdout) {
		print "sec   comp_id   name   value   len\n";
	}
	for (my $i = 5; $i < scalar @values; $i++) {
		my $value = $values[$i];
		my $name = $mname[$i];
		my $len = length $name;
		if ($stdout) {
			print "$sec   $comp_id   $name   $value   $len\n";
		} else {
			my $data = pack "L>L>d>L>a*", $sec, $comp_id, $value, $len, $name;
			send SOCK, $data, 0;
		}
	}
}

unless ($stdout) {
	close(SOCK);
}
__END__

=head1 NAME

metric_csv2baler.pl - Convert metric csv input stream and send to metric
messages to baler.

=head1 SYNOPSIS

metric_csv2baler.pl [-h host] [-p port] < INPUT_CSV
