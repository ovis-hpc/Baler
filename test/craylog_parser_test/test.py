#!/usr/bin/env python3

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
from test_util.test_util import make_store

time.tzset()

STORE_PATH = "./store"
BALERD_NUM_HOSTS = 512
BALERD_HOST_ID_BASE = 10000

log = logging.getLogger(__name__)

class Debug(object): pass

DEBUG = Debug()

def HOST_ENTRIES():
    for i in range(0, BALERD_NUM_HOSTS):
        yield "node%05d %d" % (i, BALERD_HOST_ID_BASE + i)

def RAW_MESSAGES():
    ts0 = time.strptime('2016-12-31 01:02:03', '%Y-%m-%d %H:%M:%S')
    ts0 = time.mktime(tuple(ts0))
    ts1 = list(time.strptime('Dec 31 01:02:03', '%b %d %H:%M:%S'))
    ts1[0] = time.localtime().tm_year
    ts1 = time.mktime(tuple(ts1))
    msgs = [
            "<1>1 2016-12-31T01:02:03.456789-06:00 node00001 1483167723\n",
            "<1>1 2016-12-31 01:02:03 node00002 %d\n" % ts0,
            "<1>Dec 31 01:02:03 node00003 %d\n" % ts1,
        ]
    return msgs

class TestFormat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        log.info("------- setUpClass -------")
        shutil.rmtree(STORE_PATH, ignore_errors = True)
        make_store(STORE_PATH, HOST_ENTRIES(), RAW_MESSAGES())
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
    unittest.main(failfast=True)
