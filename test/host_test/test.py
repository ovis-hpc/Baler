#!/usr/bin/env python3

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
HOST_LIST1 = [ "first%05d" % i for i in range(0, 16) ]
HOST_LIST2 = [ "second%05d" % i for i in range(0, 16) ]
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
TS_END = TS_BEGIN + 2*3600
TS_INC = 3600

def msg_iter1():
    for ts in range(TS_BEGIN, TS_END, TS_INC):
        ttxt = ts_text(ts)
        for h in HOST_LIST1:
            msg = "<1>1 %s %s First at %d\n" % (ttxt, h, ts)
            yield msg

def msg_iter2():
    for ts in range(TS_BEGIN, TS_END, TS_INC):
        ttxt = ts_text(ts)
        for h in HOST_LIST2:
            msg = "<1>1 %s %s Second at %d\n" % (ttxt, h, ts)
            yield msg

class TestRerun(unittest.TestCase):
    """Test baler daemon rerun"""

    @classmethod
    def setUpClass(cls):
        shutil.rmtree(STORE_PATH, True)
        with open(HOST_FILE, 'w') as f:
            for h in HOST_LIST1:
                print(h, file=f)
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
        sock = socket.create_connection(("localhost", PORT))
        for msg in msg_iter1():
            sock.send(msg.encode())
        sock.close()
        balerd.wait_idle()
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
        sock = socket.create_connection(("localhost", PORT))
        for msg in msg_iter2():
            sock.send(msg.encode())
        sock.close()
        balerd.wait_idle()
        balerd.stop()
        bs = bq.Bstore()
        bs.open(STORE_PATH)
        itr = bq.Bmsg_iter(bs)
        msgs = [ m for m in itr ]
        msgs_text = [ "<1>1 " + str(m) + "\n" for m in msgs ]
        msgs_text.sort()
        comp = [ s for s in msg_iter1() ] + \
               [ s for s in msg_iter2() ]
        comp.sort()
        self.assertEqual(msgs_text, comp)
        # also verify the tkn_id of hosts
        h1 = [ bs.tkn_by_name(h) for h in HOST_LIST1 ]
        h2 = [ bs.tkn_by_name(h) for h in HOST_LIST2 ]
        hosts = [ (h.tkn_id(), str(h)) for h in (h1 + h2) ]
        base = hosts[0][0]
        comp = [ (base + i, hosts[i][1]) for i in range(0, len(hosts)) ]
        self.assertEqual(hosts, comp)


if __name__ == "__main__":
    LOGFMT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
    DATEFMT = "%F %T"
    logging.basicConfig(format=LOGFMT, datefmt=DATEFMT)
    log.setLevel(logging.INFO)
    # unittest.TestLoader.testMethodPrefix = "test_"
    MAKE_STORE = True
    unittest.main(failfast=True, verbosity=2)
