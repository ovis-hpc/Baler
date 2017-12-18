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
BALERD_CFG = """
tokens type=WORD path=eng-dictionary
tokens type=HOSTNAME path=%(host_list)s
plugin name=bout_store_msg
plugin name=bout_store_hist tkn=1 ptn=1 ptn_tkn=1
plugin name=bin_tcp port=%(bin_tcp_port)s parser=syslog_parser
""" % {
    "bin_tcp_port": BIN_TCP_PORT,
    "host_list": BALERD_HOST_LIST,
}
BALERD_LOG_PATH = "./balerd.log"

PATTERNS = [
    "Pattern Zero:",
    "Pattern One:",
    "Pattern Three:",
    "Pattern Four:",
    "Pattern Five:",
    "Pattern Six:",
    "Pattern Seven:",
]

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

    hosts = [ln.strip() for ln in open(BALERD_HOST_LIST)]

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
    for h in hosts:
        for ptn in PATTERNS:
            msg = "<1>1 2016-12-31T01:02:03.456789-06:00 %s %s\n" % (
                        h, ptn
                    )
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
        bs = bq.Bstore()
        bs.open(STORE_PATH)
        # Create TAG
        self = cls
        bs.attr_new("TAG")
        pitr = bq.Bptn_iter(bs)
        self.odd_group = odd_group = set()
        self.even_group = even_group = set()
        self.three_group = three_group = set()
        # Add some tags `odd` or `even`
        for ptn in pitr:
            ptn_id = ptn.ptn_id()
            if ptn_id % 2:
                bs.ptn_attr_value_add(ptn_id, "TAG", "odd")
                odd_group.add(ptn_id)
            else:
                bs.ptn_attr_value_add(ptn_id, "TAG", "even")
                even_group.add(ptn_id)
            # to demonstrate that we can have multiple TAG values
            if ptn_id % 3 == 0:
                bs.ptn_attr_value_add(ptn_id, "TAG", "three")
                three_group.add(ptn_id)
        # NOTE Uncomment to crash the process :D
        bs.close()
        log.info("------- setUpClass COMPLETED -------")

    @classmethod
    def tearDownClass(cls):
        log.info("------- tearDownClass -------")

    def _test_query_tag(self, tag, result):
        bs = bq.Bstore()
        bs.open(STORE_PATH)
        lst = []
        log.info("These are `%s` patterns" % tag)
        aitr = bq.Bptn_attr_iter(bs)
        aitr.set_filter(attr_type = "TAG", attr_value = tag)
        for (ptn_id, attr_type, attr_value) in aitr:
            log.info(ptn_id)
            self.assertIn(ptn_id, result)
            lst.append(ptn_id)
        self.assertEqual(len(result), len(lst))
        self.assertEqual(result, set(lst))
        del aitr

    def test_query_even_tag(self):
        # Get all `even` patterns
        self._test_query_tag("even", self.even_group)

    def test_query_three_tag(self):
        # Get all `three` patterns
        self._test_query_tag("three", self.three_group)

    def test_query_odd_tag(self):
        # Get all `odd` patterns
        self._test_query_tag("odd", self.odd_group)

    def test_ptn_tags(self):
        # get tags by pattern
        bs = bq.Bstore()
        bs.open(STORE_PATH)
        log.info("pattern tags ...")
        pitr = bq.Bptn_iter(bs)
        for ptn in pitr:
            ptn_id = ptn.ptn_id()
            aitr = bq.Bptn_attr_iter(bs)
            aitr.set_filter(ptn_id = ptn_id, attr_type = "TAG")
            tags = [aval for (ptnid, atype, aval) in aitr]
            log.info("%d: %s" % (ptn_id, str(tags)))
            tagset = set(tags)
            self.assertEqual(len(tags), len(tagset))
            if ptn_id % 2:
                self.assertIn("odd", tagset)
                tagset.remove("odd")
            else:
                self.assertIn("even", tagset)
                tagset.remove("even")
            if ptn_id % 3 == 0:
                self.assertIn("three", tagset)
                tagset.remove("three")
            self.assertEqual(len(tagset), 0)


if __name__ == "__main__":
    LOGFMT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
    DATEFMT = "%F %T"
    logging.basicConfig(format=LOGFMT, datefmt=DATEFMT)
    log.setLevel(logging.INFO)
    # unittest.TestLoader.testMethodPrefix = "test_"
    unittest.main()
