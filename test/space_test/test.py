#!/usr/bin/env python

import os
import re
import sys
import time
import shutil
import socket
import logging
import unittest
import subprocess

from baler import Bq as bq

STORE_PATH = "./store"
BALERD_CFG_PATH = "./balerd.cfg"
BIN_TCP_PORT = "10514"
BALERD_HOST_LIST = "host.list"
NUM_HOSTS = 16
BALERD_CFG = """
tokens type=HOSTNAME path=%(host_list)s
tokens type=WORD path=../eng-dictionary
plugin name=bout_store_msg
plugin name=bout_store_hist tkn=1 ptn=1 ptn_tkn=1
plugin name=bin_tcp port=%(bin_tcp_port)s parser=syslog_parser
""" % {
    "bin_tcp_port": BIN_TCP_PORT,
    "host_list": BALERD_HOST_LIST,
}
BALERD_LOG_PATH = "./balerd.log"

TEMPLATE = [
    "This is Pattern One:",
    "This  is  Pattern  One:",
    "This is Pattern Two:",
    "This   is   Pattern   Two:",
    "This is Pattern Three:",
    "This    is    Pattern    Three:",
]

PATTERNS = [
    "<host> This is Pattern One: <dec>",
    "<host> This is Pattern Two: <dec>",
    "<host> This is Pattern Three: <dec>",
]

log = logging.getLogger(__name__)

class Debug(object): pass

DEBUG = Debug()

def host_generator():
    for i in range(0,NUM_HOSTS):
        yield "node%05d" % i


def msg_generator():
    count = 0
    for h in host_generator():
        for tmp in TEMPLATE:
            count += 1
            msg = "2016-12-31T01:02:03.456789-06:00 %s %s %d" % (
                        h, tmp, count
                    )
            yield msg


def make_store():
    log.info("------- making the store -------")
    cfg = open(BALERD_CFG_PATH, "w")
    print >>cfg, BALERD_CFG
    cfg.close()

    # clear blog
    blog = open(BALERD_LOG_PATH, "w")
    blog.close()

    hfile = open(BALERD_HOST_LIST, "w")
    for h in host_generator():
        print >>hfile, h
    hfile.close()

    bcmd = "balerd -F -S bstore_sos -s %(store_path)s -C %(cfg_path)s \
            -l %(log_path)s -v INFO" % {
                "store_path": STORE_PATH,
                "cfg_path": BALERD_CFG_PATH,
                "log_path": BALERD_LOG_PATH,
            }
    log.info("balerd cmd: " + bcmd)
    balerd = subprocess.Popen("exec " + bcmd, shell=True)
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
    for msg in msg_generator():
            sock.send("<1>1 " + msg + "\n")
    sock.close()
    time.sleep(1)
    log.info("Terminating balerd")
    balerd.terminate()

class TestSpace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        log.info("------- setUpClass -------")
        shutil.rmtree(STORE_PATH, ignore_errors = True)
        make_store()
        cls.bs = bq.Bstore()
        cls.bs.open(STORE_PATH)
        log.info("------- setUpClass COMPLETED -------")

    @classmethod
    def tearDownClass(cls):
        log.info("------- tearDownClass -------")

    def test_ptn(self):
        itr = bq.Bptn_iter(self.bs)
        for bptn, pptn in zip(itr, PATTERNS):
            self.assertEqual(str(bptn), pptn)

    def test_msg(self):
        itr = bq.Bmsg_iter(self.bs)
        for bmsg, pmsg in zip(itr, msg_generator()):
            self.assertEqual(str(bmsg), pmsg)


if __name__ == "__main__":
    LOGFMT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
    DATEFMT = "%F %T"
    logging.basicConfig(format=LOGFMT, datefmt=DATEFMT)
    log.setLevel(logging.INFO)
    # unittest.TestLoader.testMethodPrefix = "test_"
    unittest.main()
