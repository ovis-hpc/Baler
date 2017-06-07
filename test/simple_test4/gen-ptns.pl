#!/usr/bin/env perl
use strict;
use warnings;
use benv;
use utf8;

binmode STDOUT, ":utf8";

my @simple_word = (
	"Zero",
	"One",
	"Two",
	"Three",
	"Four",
	"Five",
	"Six",
	"Seven",
	"Eight",
	"Nine",
);

my $ptn_prefix = "This is pattern";
my $ptn_suffix = "";
for (my $i = 0; $i < $BTEST_N_TRAILING; $i++) {
	$ptn_suffix .= " \x{2022}";
}


for (my $i = 0; $i < $BTEST_N_PATTERNS; $i++) {
	print get_pattern($i), "\n";
}

exit 0;

sub get_pattern {
	glob $ptn_prefix;
	glob $ptn_suffix;
	my $ret = "$ptn_prefix";
	my ($num) = @_;
	my $dirty = 0;
	my $unit = int(100000);
	$num = int($num);
	do {
		my $x = int($num / $unit) % 10;
		$unit = int($unit / 10);
		if ($x or $dirty) {
			$ret .= " " . $simple_word[$x];
			$dirty = 1;
		}
	} while ($unit);
	if (not $dirty) {
		$ret .= " " . $simple_word[0];
	}
	$ret .= ": \x{2022} - \x{2022} \x{2022}$ptn_suffix";
	# ts - node LONG_TKN TRAILING_TKNS
	return $ret;
}
