#!/usr/bin/env python
import os
import sys
import re
import time
import unittest
from dateutil import parser as ts_parser
from test_util import util

def input_iter():
    for fname in os.listdir(util.BTEST_INPUT_DIR):
        path = util.BTEST_INPUT_DIR + "/" + fname
        f = open(path)
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

class TestMsgs(unittest.TestCase):
    def testMsgs(self):
        inp = [Msg.fromText(x) for x in input_iter()]
        inp.sort()
        bs = util.BStore.open("bstore_sos", util.BSTORE, os.O_RDWR, 0)
        itr = util.MsgIter(bs)
        outp = [Msg.fromUtilMsg(x) for x in itr]
        outp.sort()
        self.assertEqual(inp, outp)

if __name__ == "__main__":
    unittest.main()
