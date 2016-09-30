#!/usr/bin/python
import os
import sys
import subprocess

def get_benv():
    keys = [
        "BSTORE",
        "BSTORE_PLUGIN",
        "BSTAT",
        "BSTATM",
        "BCONFIG",
        "BTEST_ENG_DICT",
        "BTEST_HOST_LIST",
        "BTEST_BIN_RSYSLOG_PORT",
        "BTEST_TS_BEGIN",
        "BTEST_TS_LEN",
        "BTEST_TS_INC",
        "BTEST_NODE_BEGIN",
        "BTEST_NODE_LEN",
        "BTEST_N_PATTERNS",
        "BOUT_THREADS",
        "BIN_THREADS",
        "BLOG_LEVEL",
        "PATH",
        "LD_LIBRARY_PATH",
        "ZAP_LIBPATH",
        "PYTHONPATH",
        "BSTORE_PLUGIN_PATH"
    ]
    benv = {}
    proc = subprocess.Popen("/bin/bash", stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE)
    proc.stdin.write("""
            { [ -f config.sh ] && source config.sh ; } ||
            { [ -f ../config.sh ] && cd ../ && source config.sh ; } ||
            exit 1
        """)
    for k in keys:
        proc.stdin.write("echo $%s\n" % k)
        val = proc.stdout.readline().strip()
        benv[k] = val
    return benv
