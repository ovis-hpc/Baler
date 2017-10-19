#!/bin/bash

# STDERR => STDOUT
exec 2>&1

# Default values
BLOG=./balerd.log
BSTORE=./store
BCONFIG=./balerd.cfg
BTEST_N_PATTERNS=128
BTEST_ENG_DICT="../eng-dictionary"
BTEST_HOST_LIST="../host.list"
BTEST_BIN_RSYSLOG_PORT=33333
BSTORE_PLUGIN="bstore_sos"
BPROF=balerd.prof

BOUT_THREADS=1
BIN_THREADS=1
BLOG_LEVEL=INFO

BTEST_BLOCKING_MQ=1  # 1==on, 0==off
BTEST_MQ_THREADS=4
BTEST_MQ_DEPTH=128
BTEST_TKN_HIST=1
BTEST_PTN_HIST=1
BTEST_PTN_TKN=1
BTEST_CHECK='X'
BTEST_OPERF='X'

E_CODE=1

source ./common.sh

__check_config "$0"

# balerd.cfg generation
{
_TMP=$(type -t get_btest_config)
if [[ -n "$_TMP" ]] && [[ "$_TMP" = "function" ]]; then
	get_btest_config
else
	cat <<EOF
tokens type=WORD path=$BTEST_ENG_DICT
tokens type=WORD path=$BTEST_HOST_LIST
plugin name=bout_store_msg
plugin name=bout_store_hist \
       blocking_mq=$BTEST_BLOCKING_MQ \
       threads=$BTEST_MQ_THREADS \
       q_depth=$BTEST_MQ_DEPTH \
       tkn=$BTEST_TKN_HIST \
       ptn=$BTEST_PTN_HIST \
       ptn_tkn=$BTEST_PTN_TKN
plugin name=bin_tcp port=$BTEST_BIN_RSYSLOG_PORT parser=syslog_parser
EOF
fi
} > $BCONFIG

BALERD_OPTS="-S $BSTORE_PLUGIN -s $BSTORE -l $BLOG \
	     -C $BCONFIG -v $BLOG_LEVEL \
	     -I $BIN_THREADS -O $BOUT_THREADS"
BALERD_CMD="balerd -F $BALERD_OPTS"

BPID=0

check_balerd() {
	jobs '%$BALERD_CMD' > /dev/null 2>&1 || \
		__err_exit "balerd is not running"
	# repeat to cover the "Done" case.
	sleep 1
	jobs '%$BALERD_CMD' > /dev/null 2>&1 || \
		__err_exit "balerd is not running"
}

wait_balerd() {
	echo "waiting ..."

	if (( ! BPID )); then
		echo "wait_balerd -- WARN: BPID not set"
		return
	fi
	P=`top -p $BPID -b -n 1 | grep 'balerd' | awk '{print $9}' | cut -f 1 -d .`
	while (( P > 10 )); do
		sleep 1
		X=($(top -p $BPID -b -n 1 | tail -n 1))
		P=${X[8]%%.*}
	done
	if __use_operf; then
		pkill -s 0 -SIGINT operf
	fi
}

stat_balerd() {
	if (( ! BPID )); then
		echo "stat_balerd -- WARN: BPID not set"
		return
	fi

	if __use_operf; then
		if [[ -d "$BPROF" ]]; then
			rm -rf $BPROF
		fi
		mkdir -p $BPROF
		operf --callgraph --session-dir $BPROF \
			--pid $BPID >/dev/null 2>&1 &
	fi

	while true; do
		DT=$(date)
		ST=$(cat /proc/$BPID/stat)
		STM=$(cat /proc/$BPID/statm)
		echo $DT $ST >> $BSTAT
		echo $DT $STM >> $BSTATM
		sleep 1;
	done
}

if [[ -d $BSTORE ]]; then
	X=`lsof +D $BSTORE | grep '^balerd' | wc -l`
	if ((X)); then
		__err_exit "Another balerd is running with the store: $BSTORE"
	fi
fi

exit_hook() {
	pkill -P $$
	return $E_CODE
}

# Hook to kill all jobs at exit
trap 'exit_hook' EXIT
# trap ':' SIGTERM

./clean.sh

__info "starting balerd, cmd: $BALERD_CMD"
$BALERD_CMD &

sleep 1

check_balerd

BPID=`jobs -p '%$BALERD_CMD'`

stat_balerd &

__info "baler PID: $BPID"

if [[ -t 1 ]]; then
	__info "Press ENTER to start sending data to balerd ..."
	read
fi

__info "sending data to balerd"

# stat_balerd &

sleep 1

time -p ./gen-log.pl | ./syslog2baler.pl -p $BTEST_BIN_RSYSLOG_PORT

if (( $? )); then
	__err_exit "Cannot send data to balerd."
fi

__info "done sending data .. wait a little while for balerd to process them"

time -p wait_balerd

sleep 1

check_balerd

__info "BTEST_CHECK: $BTEST_CHECK"
if [[ -n "$BTEST_CHECK" ]]; then
	__info "NOTE: To disable checking, set BTEST_CHECK to '' (or unset it)"
	__info "Checking ..."
	./check.sh
	E_CODE=$?
else
	__info "BTEST_CHECK not set. To enable checking, set BTEST_CHECK to a non-empty string"
	E_CODE=0
fi

sleep 1

echo -e "${BLD}${GRN}FINISHED!!!${NC}"

if [[ -t 1 ]]; then
__info "Press ENTER to exit ..."
read
fi

exit $E_CODE
