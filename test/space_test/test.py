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
from test_util.test_util import ts_text, make_store

STORE_PATH = "./store"
NUM_HOSTS = 16

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

time.tzset()

class Debug(object): pass

DEBUG = Debug()

def host_generator():
    for i in range(0,NUM_HOSTS):
        yield "node%05d" % i

def msg_generator():
    count = 0
    ts_str = ts_text(1483167723, 456789)
    for h in host_generator():
        for tmp in TEMPLATE:
            count += 1
            msg = "%s %s %s %d" % ( ts_str, h, tmp, count )
            yield msg

def RAW_MESSAGES():
    for msg in msg_generator():
        yield "<1>1 " + msg + "\n"

class TestSpace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        log.info("------- setUpClass -------")
        shutil.rmtree(STORE_PATH, ignore_errors = True)
        make_store(STORE_PATH, host_generator(), RAW_MESSAGES())
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
