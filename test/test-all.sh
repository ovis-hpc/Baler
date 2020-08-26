#!/bin/bash

XMLRUNNER=$1

set -e
LIST=(
simple_test
bq
bq_ptn_attr
craylog_parser_test
host_test
ptn_attr_test
rerun_test
space_test
syslog_parser_test
token_alias_test4
)

header() {
	local TXT=$1
	local LEN=${2:-70}
	local TXT_LEN=${#TXT}
	local DASH_LEN=$(((LEN - TXT_LEN)/2 - 1))
	local DASH
	local FULL_DASH
	eval "printf -v DASH ' %.0s' {1..$DASH_LEN}"
	eval "printf -v FULL_DASH '~%.0s' {1..$LEN}"
	echo "$FULL_DASH"
	echo "$DASH $TXT $DASH"
	echo "$FULL_DASH"
}

footer() {
	local TXT=$1
	local LEN=${2:-70}
	local TXT_LEN=${#TXT}
	local DASH_LEN=$(((LEN - TXT_LEN)/2 - 1))
	local DASH
	local FULL_DASH
	eval "printf -v DASH ' %.0s' {1..$DASH_LEN}"
	eval "printf -v FULL_DASH '~%.0s' {1..$LEN}"
	echo ""
	echo "$DASH $TXT $DASH"
	echo "$FULL_DASH"
}

for X in ${LIST[*]}; do
	pushd $X
	echo ""
	header "BEGIN $X"
	if [[ -e test.py ]]; then
		if [[ -z $XMLRUNNER ]]; then
			./test.py -v
		else
			echo "xmlrunner"
			rm -fr *.xml
			python -m xmlrunner -v test
		fi
	else
		./run-test.sh
	fi
	PIDS=$(pgrep -x balerd || true)
	if [[ -n "$PID" ]]; then
		echo "ERROR: There is an left-over baler daemon from last test"
		echo "       PIDS: $PIDS"
		exit -1
	fi
	footer "END $X"
	echo ""
	popd
done
