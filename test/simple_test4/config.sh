#!/bin/bash

export BLOG=./balerd.log
export BSTORE=./store
export BSTORE_PLUGIN="bstore_sos"
export BSTAT=./balerd.stat
export BSTATM=./balerd.statm
export BCONFIG=./balerd.cfg
# Baler configuration file (balerd.cfg) will be automatically generated.

export BTEST_ENG_DICT="../eng-dictionary"
export BTEST_HOST_LIST="../host.list"
export BTEST_BIN_RSYSLOG_PORT=10514
export BTEST_TS_BEGIN=1435294800
export BTEST_TS_LEN=$((3600*24))
export BTEST_TS_INC=1800
export BTEST_NODE_BEGIN=0
export BTEST_NODE_LEN=17
export BTEST_N_PATTERNS=8
export BTEST_N_TRAILING=2
export BTEST_LONG_TOKEN_LEN=128 # must be > 0

export BTEST_BIN_MAX_MSG_LEN=0

export BTEST_BLOCKING_MQ=1  # 1==on, 0==off
export BTEST_MQ_THREADS=4
export BTEST_MQ_DEPTH=128

# hist store flags: 1==on 0==off
export BTEST_TKN_HIST=1
export BTEST_PTN_HIST=1
export BTEST_PTN_TKN=2

# Flag to run check scripts: 'X'==on ''==off
export BTEST_CHECK='X'

# Flag to run operf (oprofile): 'X'==on ''==off
export BTEST_OPERF=''

export BOUT_THREADS=2
export BIN_THREADS=2
export BLOG_LEVEL=INFO

export BTEST_TKN_TYPE_MASK="''"

source env.sh

get_btest_config() {
	cat <<EOF
tokens type=HOSTNAME path=$BTEST_HOST_LIST
tokens type=HOSTNAME path=$BTEST_HOST_LIST
tokens type=WORD path=$BTEST_ENG_DICT
plugin name=bout_store_msg
plugin name=bout_store_hist \
       blocking_mq=$BTEST_BLOCKING_MQ \
       threads=$BTEST_MQ_THREADS \
       q_depth=$BTEST_MQ_DEPTH \
       tkn=$BTEST_TKN_HIST \
       tkn_type_mask=$BTEST_TKN_TYPE_MASK \
       ptn=$BTEST_PTN_HIST \
       ptn_tkn=$BTEST_PTN_TKN
plugin name=bin_tcp port=$BTEST_BIN_RSYSLOG_PORT parser=syslog_parser \
       max_msg_len=$BTEST_BIN_MAX_MSG_LEN
EOF
}

export -f get_btest_config
