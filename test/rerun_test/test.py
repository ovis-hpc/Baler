#!/usr/bin/env python

import os
import sys
import time
import shutil
import socket
import logging
import unittest

from test_util.test_util import ts_text, BalerDaemon

from baler import Bq as bq

log = logging.getLogger(__name__)

HOST_FILE = "host.list"
HOST_LIST = [ "node%05d" % i for i in range(0, 1) ]
PORT = "10514"
CONFIG_TEXT = """
tokens type=HOSTNAME path=%(host_file)s
tokens type=WORD path=eng-dictionary
plugin name=bout_store_msg
plugin name=bout_store_hist tkn=1 ptn=1 ptn_tkn=1
plugin name=bin_tcp port=%(bin_tcp_port)s parser=syslog_parser
""" % {
    "bin_tcp_port": PORT,
    "host_file": HOST_FILE,
}
CONFIG_FILE = "balerd.cfg"
STORE_PATH = "store"
BALERD_LOG = "balerd.log"
TS_BEGIN = 1531785600
TS_END = TS_BEGIN + 1*3600
TS_INC = 3600

def msg_iter1():
    for ts in range(TS_BEGIN, TS_END, TS_INC):
        ttxt = ts_text(ts)
        for h in HOST_LIST:
            for n in range(0, 16):
                msg = "<1>1 %s %s Number: first%d\n" % (ttxt, h, n)
                yield msg

def msg_iter2():
    for ts in range(TS_BEGIN, TS_END, TS_INC):
        ttxt = ts_text(ts)
        for h in HOST_LIST:
            for n in range(0, 16):
                msg = "<1>1 %s %s Number: second%d\n" % (ttxt, h, n)
                yield msg

class TestRerun(unittest.TestCase):
    """Test baler daemon rerun"""

    @classmethod
    def setUpClass(cls):
        shutil.rmtree(STORE_PATH, True)
        with open(HOST_FILE, 'w') as f:
            for h in HOST_LIST:
                print >>f, h
        with open(CONFIG_FILE, 'w') as f:
            f.write(CONFIG_TEXT)

    @classmethod
    def tearDownClass(cls):
        pass

    def test_001_first_batch(self):
        balerd = BalerDaemon(STORE_PATH, config_file = CONFIG_FILE,
                                         log_file = BALERD_LOG,
                                         log_verbosity = "INFO")
        balerd.start()
        time.sleep(1)
        sock = socket.create_connection(("localhost", PORT))
        for msg in msg_iter1():
            sock.send(msg)
        sock.close()
        time.sleep(1)
        balerd.stop()
        bs = bq.Bstore()
        bs.open(STORE_PATH)
        itr = bq.Bmsg_iter(bs)
        msgs = [ "<1>1 " + str(m) + "\n" for m in itr ]
        msgs.sort()
        comp = [ s for s in msg_iter1() ]
        comp.sort()
        self.assertEqual(msgs, comp)

    def test_002_second_batch(self):
        balerd = BalerDaemon(STORE_PATH, config_file = CONFIG_FILE,
                                         log_file = BALERD_LOG,
                                         log_verbosity = "INFO")
        balerd.start()
        time.sleep(1)
        sock = socket.create_connection(("localhost", PORT))
        for msg in msg_iter2():
            sock.send(msg)
        sock.close()
        time.sleep(1)
        balerd.stop()
        bs = bq.Bstore()
        bs.open(STORE_PATH)
        itr = bq.Bmsg_iter(bs)
        msgs = [ m for m in itr ]
        msg_tkns = [ [t for t in m] for m in msgs ]
        tkns = [ m[-1] for m in msg_tkns ]
        tkns0 = []
        tkns1 = []
        for t in tkns:
            s = str(t)
            if s.startswith("first"):
                tkns0.append(t)
            elif s.startswith("second"):
                tkns1.append(t)
            else:
                raise ValueError("Unexpected token: %s" % s)
        first = max(x.tkn_id() for x in tkns0)
        second = min(x.tkn_id() for x in tkns1)
        self.assertLess(first, second)
        msgs_text = [ "<1>1 " + str(m) + "\n" for m in msgs ]
        msgs_text.sort()
        comp = [ s for s in msg_iter1() ] + \
               [ s for s in msg_iter2() ]
        comp.sort()
        self.assertEqual(msgs_text, comp)


if __name__ == "__main__":
    LOGFMT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
    DATEFMT = "%F %T"
    logging.basicConfig(format=LOGFMT, datefmt=DATEFMT)
    log.setLevel(logging.INFO)
    # unittest.TestLoader.testMethodPrefix = "test_"
    MAKE_STORE = True
    unittest.main()
