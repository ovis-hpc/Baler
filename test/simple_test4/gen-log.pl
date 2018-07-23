#!/usr/bin/env perl
use lib ".";
use strict;
use warnings;
use POSIX qw(strftime);
use benv;
use utf8;

my ($TS, $N, $I);

# Load patterns
open my $fin, "./gen-ptns.pl |" or die "Cannot run ./gen-ptns.pl script";
binmode $fin, ":utf8";
my @PTNS = <$fin>;

# for my $P (@PTNS) {
# 	chomp $P;
# 	$P =~ s/\x{2022}/\%d/g;
# }

my @TSTA = ();
my @NODES = ();

my $tz = strftime("%z", localtime($BTEST_TS_BEGIN));
$tz =~ s/([+-]\d\d)(\d\d)/$1:$2/;

for ($TS=0; $TS<$BTEST_TS_LEN; $TS+=$BTEST_TS_INC) {
	my @tm = localtime($BTEST_TS_BEGIN + $TS);
	my $TS_TEXT = strftime "%FT%T.000000$tz", @tm;
	push @TSTA, $TS_TEXT;
}

for ($N=0; $N<$BTEST_NODE_LEN; $N++) {
	my $NODE = sprintf 'node%05d', $N+$BTEST_NODE_BEGIN;
	push @NODES, $NODE;
}

my $LONG_TKN = "";

for ($I=0; $I<$BTEST_LONG_TOKEN_LEN; $I+=1) {
	$LONG_TKN .= "9";
}


my $num = 0;

my $NP;

$TS = int($BTEST_TS_BEGIN);
for my $TS_TEXT (@TSTA) {
	$NP = 0;
	for my $PTN (@PTNS) {
		$N=$BTEST_NODE_BEGIN;
		for my $NODE (@NODES) {
			if ($N % scalar(@PTNS) != $NP) {
				my $text = "$TS_TEXT $NODE $PTN";
				$text =~ s/\x{2022}/$TS/;
				$text =~ s/\x{2022}/$LONG_TKN/;
				$text =~ s/\x{2022}/$N/g;
				print $text;
				$num++;
			}
			$N++;
		}
		$NP++;
	}
	$TS += int($BTEST_TS_INC);
}

print STDERR "total messages: $num\n";
exit 0
