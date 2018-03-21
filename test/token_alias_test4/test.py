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

from distutils.spawn import find_executable

from baler import Bq as bq
from baler import util

STORE_PATH = "./store"
BALERD_CFG_PATH = "./balerd.cfg"
BIN_TCP_PORT = "10514"
BALERD_HOST_LIST = "host.list"
BALERD_CFG = """
tokens type=HOSTNAME path=%(host_list)s
tokens type=WORD path=eng-dictionary
plugin name=bout_store_msg
plugin name=bout_store_hist tkn=1 ptn=1 ptn_tkn=1
plugin name=bin_tcp port=%(bin_tcp_port)s parser=syslog_parser
""" % {
    "bin_tcp_port": BIN_TCP_PORT,
    "host_list": BALERD_HOST_LIST,
}
BALERD_LOG_PATH = "./balerd.log"
BALERD_MSG_LOG = "./msg.log"

PATTERNS = [
    "Pattern Zero:",
    "Pattern One:",
    "Pattern Three:",
    "Pattern Four:",
    "Pattern Five:",
    "Pattern Six:",
    "Pattern Seven:",
]

# major_name, alias, ID
hosts = [
    ("node0001", "alias0001", 10001),
    ("node0002", "alias0002", 10002),
    ("node0003", "alias0003", 10003),
    ("node0004", "alias0004", 10004),
    ("node0005", "alias0005", 10005),
    ("node0006", "alias0006", 10006),
    ("node0007", "alias0007", 10007),
    ("node0008", "alias0008", 10008),
    ("node0009", "alias0009", 10009),
    ("node0010", "alias0010", 10010),
    ("node0011", "alias0011", 10011),
    ("node0012", "alias0012", 10012),
    ("node0013", "alias0013", 10013),
    ("node0014", "alias0014", 10014),
    ("node0015", "alias0015", 10015),
    ("node0016", "alias0016", 10016),
]

log = logging.getLogger(__name__)

class Debug(object): pass

DEBUG = Debug()

ENABLE_GDB = False

def msg_generator():
    count = 0
    ts = util.Timestamp.fromStr("2016-12-31T01:02:03.456789")
    ts_str = str(ts)
    global hosts
    for h, alias, tkn_id in hosts:
        for ptn in PATTERNS:
            for name in [h, alias]:
                count += 1
                msg = "<1>1 %s %s %s %d\n" % (
                            ts_str, name, ptn, count
                        )
                yield msg

def make_store():
    global hosts
    log.info("------- making the store -------")
    cfg = open(BALERD_CFG_PATH, "w")
    print >>cfg, BALERD_CFG
    cfg.close()

    hf = open(BALERD_HOST_LIST, "w")
    for name, alias, tkn_id in hosts:
        print >>hf, alias, tkn_id
        print >>hf, name, tkn_id
    hf.close()

    # clear blog
    blog = open(BALERD_LOG_PATH, "w")
    blog.close()

    balerd_bin = find_executable("balerd")
    if not balerd_bin:
        raise RuntimeError("balerd not found")

    bcmd = []

    if ENABLE_GDB:
        bcmd.extend(["gdbserver", ":20001"])

    bcmd.extend([
        balerd_bin,
        "-F",
        "-S", "bstore_sos",
        "-s", STORE_PATH,
        "-C", BALERD_CFG_PATH,
        "-l", BALERD_LOG_PATH,
        "-v", "INFO",
    ])

    log.info("balerd cmd: " + str(bcmd))
    balerd = subprocess.Popen(bcmd,
                              stdin=open(os.devnull, "r"),
                              stdout=open(os.devnull, "w"),
                              stderr=open(os.devnull, "w"),
                              close_fds = True,
                              )
    if ENABLE_GDB:
        raw_input("Press ENTER after attached the gdb")
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

    mlog = open(BALERD_MSG_LOG, "w")

    # now, feed some data to the daemon
    log.info("Feeding data to balerd")
    sock = socket.create_connection(("localhost", BIN_TCP_PORT))
    for msg in msg_generator():
        print >>mlog, msg
        sock.send(msg)
    sock.close()
    time.sleep(1)
    log.info("Terminating balerd")
    balerd.terminate()

class TestAttr(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        log.info("------- setUpClass -------")
        shutil.rmtree(STORE_PATH, ignore_errors = True)
        make_store()
        log.info("------- setUpClass COMPLETED -------")

    @classmethod
    def tearDownClass(cls):
        log.info("------- tearDownClass -------")

    def test_alias(self):
        bs = bq.Bstore()
        DEBUG.bs = bs
        bs.open(STORE_PATH)
        data0 = [ str(msg) for msg in bq.Bmsg_iter(bs) ]
        data1 = [ msg.strip().replace("<1>1 ", "", 1).replace("alias", "node")
                                    for msg in msg_generator() ]
        DEBUG.data0 = data0
        DEBUG.data1 = data1
        self.assertEqual(data0, data1)


if __name__ == "__main__":
    pystart = os.getenv("PYTHONSTARTUP")
    if pystart:
        execfile(pystart)
    LOGFMT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
    DATEFMT = "%F %T"
    logging.basicConfig(format=LOGFMT, datefmt=DATEFMT)
    log.setLevel(logging.INFO)
    # unittest.TestLoader.testMethodPrefix = "test_"
    unittest.main(
                verbosity=2,
                failfast=True,
        )
