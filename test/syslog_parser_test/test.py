#!/usr/bin/env python3

import os
import re
import sys
import time
import shutil
import socket
import logging
import unittest

from functools import total_ordering

from dateutil import parser as ts_parser
from test_util.test_util import ts_text, BalerDaemon
from test_util import util

from baler import Bq as bq

log = logging.getLogger(__name__)

PORT = "10514"
CONFIG_TEXT = """
tokens type=WORD path=eng-dictionary
plugin name=bout_store_msg
plugin name=bout_store_hist tkn=1 ptn=1 ptn_tkn=1
plugin name=bin_tcp port=%(bin_tcp_port)s parser=syslog_parser
""" % {
    "bin_tcp_port": PORT,
}
STORE_PATH = "store"
BALERD_LOG = "balerd.log"
LOGFILES = [
      "log/hwerr.txt",
      "log/syslog1.txt",
      "log/syslog2.txt",
      "log/syslog3.txt",
      "log/syslog4.txt",
]
MAKE_STORE = True

def input_iter():
    for name in LOGFILES:
        with open(name, "r") as f:
            for l in f:
                yield l.strip()

RE_SYSLOG0 = re.compile(
    "^(?:<\d+>)?(%(months)s +\d{1,2} +\d\d:\d\d:\d\d) (.*)$" % {
        "months": "(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)",
    }
)

RE_SYSLOG1 = re.compile(
    "^(?:<\d+>\d+ )?(%(ts)s%(us)s%(tz)s) (.*)$" % {
        "ts": "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
        "us":  "(?:\\.\d{6})?",
        "tz": "(?:Z|[+-]\d\d:\d\d)",
    }
)
RE_CRAY = re.compile("^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (.*)$")

EPOCH = ts_parser.parse("1970-01-01T00:00:00.000000-00:00")

def parse_ts(s):
    ts = ts_parser.parse(s)
    if ts.tzinfo:
        dt = ts - EPOCH
        return dt.total_seconds()
    return time.mktime(ts.timetuple())

@total_ordering
class Msg(object):
    __slots__ = ["ts", "text"]

    def __init__(self, ts, text):
        assert(type(ts) == float or type(ts) == int)
        self.ts = ts
        self.text = text

    def __cmp__(self, other):
        assert(type(other) == Msg)
        if self.ts < other.ts:
            return -1
        if self.ts > other.ts:
            return 1
        if self.text < other.text:
            return -1
        if self.text > other.text:
            return 1
        return 0

    def __eq__(self, other):
        return self.__cmp__(other) == 0

    def __lt__(self, other):
        return self.__cmp__(other) < 0

    def __str__(self):
        return "%.06f %s" % (self.ts, self.text)

    def __repr__(self):
        return "Msg(%.06f, %s)" % (self.ts, self.text)

    @classmethod
    def fromUtilMsg(cls, umsg):
        return Msg(umsg.timestamp, umsg.text())

    @classmethod
    def fromText(cls, text):
        global RE_SYSLOG0, RE_SYSLOG1, RE_CRAY
        ts = None
        msg = None
        for r in [RE_SYSLOG0, RE_SYSLOG1, RE_CRAY]:
            m = r.match(text)
            if m:
                (ts, msg) = m.groups()
                break
        if msg == None:
            raise ValueError("Unsupported format")
        ts = parse_ts(ts)
        return Msg(ts, msg)

#### end class Msg ####


class TestSyslogParser(unittest.TestCase):
    """Test syslog parser"""

    @classmethod
    def _make_store(cls):
        shutil.rmtree(STORE_PATH, True)
        # start balerd
        balerd = BalerDaemon(STORE_PATH, config_text = CONFIG_TEXT,
                                         log_file = BALERD_LOG,
                                         log_verbosity = "INFO")
        balerd.start()
        # feed data to balerd
        for name in LOGFILES:
            with open(name, "r") as f:
                sock = socket.create_connection(("localhost", PORT))
                for l in f:
                    sock.send(l.encode())
                sock.close()
        balerd.wait_idle()
        balerd.stop()

    @classmethod
    def setUpClass(cls):
        if MAKE_STORE:
            cls._make_store()

    @classmethod
    def tearDownClass(cls):
        pass

    def testMsgs(self):
        inp = [Msg.fromText(x) for x in input_iter()]
        inp.sort()
        bs = util.BStore.open("bstore_sos", STORE_PATH, os.O_RDWR, 0)
        itr = util.MsgIter(bs)
        outp = [Msg.fromUtilMsg(x) for x in itr]
        outp.sort()
        self.assertEqual(inp, outp)

if __name__ == "__main__":
    LOGFMT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
    DATEFMT = "%F %T"
    logging.basicConfig(format=LOGFMT, datefmt=DATEFMT)
    log.setLevel(logging.INFO)
    # unittest.TestLoader.testMethodPrefix = "test_"
    MAKE_STORE = True
    unittest.main(verbosity=2, failfast=1)
