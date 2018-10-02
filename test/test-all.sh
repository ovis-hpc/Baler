#!/bin/bash

set -e
LIST=(
simple_test4
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

for X in ${LIST[*]}; do
	pushd $X
	echo "###### BEGIN $X ######"
	if [[ -e test.py ]]; then
		./test.py -f -v
	else
		./run-test.sh
	fi
	PIDS=$(pgrep -x balerd || true)
	if [[ -n "$PID" ]]; then
		echo "ERROR: There is an left-over baler daemon from last test"
		echo "       PIDS: $PIDS"
		exit -1
	fi
	echo "###### END $X ######"
	popd
done
