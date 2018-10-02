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
from test_util.test_util import make_store

STORE_PATH = "./store"

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
HOSTS = [
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

def HOST_ENTRIES():
    for name, alias, tkn_id in HOSTS:
        yield "%s %d" % (alias, tkn_id)
        yield "%s %d" % (name, tkn_id)

log = logging.getLogger(__name__)

class Debug(object): pass

DEBUG = Debug()

ENABLE_GDB = False

def msg_generator():
    count = 0
    ts = util.Timestamp.fromStr("2016-12-31T01:02:03.456789")
    ts_str = str(ts)
    global HOSTS
    for h, alias, tkn_id in HOSTS:
        for ptn in PATTERNS:
            for name in [h, alias]:
                count += 1
                msg = "<1>1 %s %s %s %d\n" % (
                            ts_str, name, ptn, count
                        )
                yield msg

class TestAttr(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        log.info("------- setUpClass -------")
        shutil.rmtree(STORE_PATH, ignore_errors = True)
        make_store(STORE_PATH, HOST_ENTRIES(), msg_generator())
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
