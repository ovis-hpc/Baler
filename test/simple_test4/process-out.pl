#!/usr/bin/env perl
use strict;
use warnings;

my $first = 1;

print "label,run,send_msg,wait_msg,check-img,check-log,check-ptn\n";

if (@ARGV) {
	map { process_file($_); } @ARGV;
} else {
	process_fh("stdin", *STDIN);
}

exit 0;

sub process_file {
	my ($fname) = @_;
	open my $file, "<$fname" or die "Cannot open file: $fname";
	process_fh($fname, $file);
}

sub process_fh {
	my ($fname, $file) = @_;
	my ($label, $run);
	if ($fname =~ m/(.*)\.(\d+)/) {
		$label = $1;
		$run = $2;
	} else {
		$label = $fname;
		$run = 0;
	}
	while (my $line = <$file>) {
		chomp $line;
		if ($line =~ m/^INFO: starting balerd/) {
			if (not $first) {
				print "\n";
			}
			print "$label,$run";
			$first = 0;
		} elsif ($line =~ m/^real\s+(\d+(.\d+)?)/) {
			print ",$1";
		}
	}
}
