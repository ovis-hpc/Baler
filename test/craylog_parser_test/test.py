#!/usr/bin/env python

import os
import re
import pdb
import sys
import time
import shutil
import socket
import logging
import unittest
import subprocess

from baler import Bq as bq

time.tzset()

STORE_PATH = "./store"
BALERD_CFG_PATH = "./balerd.cfg"
BIN_TCP_PORT = "10514"
BALERD_NUM_HOSTS = 512
BALERD_HOST_ID_BASE = 10000
BALERD_HOST_FILE = "host.file"
BALERD_CFG = """
tokens type=HOSTNAME path=%(host_file)s
tokens type=WORD path=eng-dictionary
plugin name=bout_store_msg
plugin name=bout_store_hist tkn=1 ptn=1 ptn_tkn=1
plugin name=bin_tcp port=%(bin_tcp_port)s parser=syslog_parser
""" % {
    "bin_tcp_port": BIN_TCP_PORT,
    "host_file": BALERD_HOST_FILE,
}
BALERD_LOG_PATH = "./balerd.log"

log = logging.getLogger(__name__)

class Debug(object): pass

DEBUG = Debug()

def make_store():
    log.info("------- making the store -------")
    cfg = open(BALERD_CFG_PATH, "w")
    print >>cfg, BALERD_CFG
    cfg.close()

    # clear blog
    blog = open(BALERD_LOG_PATH, "w")
    blog.close()

    with open(BALERD_HOST_FILE, "w") as f:
        for i in range(0, BALERD_NUM_HOSTS):
            print >>f, ("node%05d" % i), BALERD_HOST_ID_BASE + i

    bcmd = "balerd -F -S bstore_sos -s %(store_path)s -C %(cfg_path)s \
            -l %(log_path)s -v INFO" % {
                "store_path": STORE_PATH,
                "cfg_path": BALERD_CFG_PATH,
                "log_path": BALERD_LOG_PATH,
            }
    log.info("balerd cmd: " + bcmd)
    balerd = subprocess.Popen("exec " + bcmd, shell=True)
    try:
        pos = 0
        is_ready = False
        ready_re = re.compile(".* Baler is ready..*")
        # look for "Baler is ready" in the log
        while True:
            x = balerd.poll()
            if balerd.returncode != None:
                # balerd terminated
                break
            blog = open(BALERD_LOG_PATH, "r")
            blog.seek(pos, 0)
            ln = blog.readline()
            if not ln:
                pos = blog.tell()
                blog.close()
                time.sleep(0.1)
                continue
            m = ready_re.match(ln)
            if m:
                is_ready = True
                blog.close()
                break
            pos = blog.tell()
            blog.close()

        if not is_ready:
            raise Exception("Something bad happened to balerd")

        # now, feed some data to the daemon
        log.info("Feeding data to balerd")
        sock = socket.create_connection(("localhost", BIN_TCP_PORT))
        ts0 = time.strptime('2016-12-31 01:02:03', '%Y-%m-%d %H:%M:%S')
        ts0 = time.mktime(ts0)
        ts1 = list(time.strptime('Dec 31 01:02:03', '%b %d %H:%M:%S'))
        ts1[0] = time.localtime().tm_year
        ts1 = time.mktime(ts1)
        msgs = """\
<1>1 2016-12-31T01:02:03.456789-06:00 node00001 1483167723
<1>1 2016-12-31 01:02:03 node00002 %(ts0)d
<1>Dec 31 01:02:03 node00003 %(ts1)d
    """ % {
            "ts0": ts0,
            "ts1": ts1,
        }
        sock.send(msgs)
        sock.close()
        time.sleep(1)
        log.info("Terminating balerd")
    finally:
        balerd.terminate()
        balerd.wait()

class TestFormat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        log.info("------- setUpClass -------")
        shutil.rmtree(STORE_PATH, ignore_errors = True)
        make_store()
        log.info("------- setUpClass COMPLETED -------")

    @classmethod
    def tearDownClass(cls):
        log.info("------- tearDownClass -------")

    def test_01_bla(self):
        bs = bq.Bstore()
        bs.open(STORE_PATH)
        itr = bq.Bmsg_iter(bs)
        for m in itr:
            sec = m.tv_sec()
            s = str(m)
            _sec = s.split(' ')[-1]
            _sec = int(_sec)
            self.assertEqual(_sec, sec)


if __name__ == "__main__":
    LOGFMT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
    DATEFMT = "%F %T"
    logging.basicConfig(format=LOGFMT, datefmt=DATEFMT)
    log.setLevel(logging.INFO)
    # unittest.TestLoader.testMethodPrefix = "test_"
    unittest.main()
