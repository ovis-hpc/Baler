#!/usr/bin/env python3

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
from test_util.test_util import make_store

STORE_PATH = "./store"

HOSTS = [ "node%05d" % i for i in range(1, 17) ]

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

def RAW_MESSAGES():
    for h in HOSTS:
        for ptn in PATTERNS:
            msg = "<1>1 2016-12-31T01:02:03.456789-06:00 %s %s\n" % (h, ptn)
            yield msg

class TestAttr(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        log.info("------- setUpClass -------")
        shutil.rmtree(STORE_PATH, ignore_errors = True)
        make_store(STORE_PATH, HOSTS, RAW_MESSAGES())
        bs = bq.Bstore()
        bs.open(STORE_PATH)
        # Create TAG
        self = cls
        bs.attr_new("TAG")
        bs.attr_new("ATTR0")
        bs.attr_new("ATTR1")
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

    def test_attr_iter(self):
        bs = bq.Bstore()
        bs.open(STORE_PATH)
        ai = bq.Battr_iter(bs)
        attr_types = [ x for x in ai ]
        attr_types.sort()
        expect = ["TAG", "ATTR0", "ATTR1"]
        expect.sort()
        self.assertEqual(attr_types, expect)
        log.info("attr types: %s" % str(attr_types))
        del ai
        bs.close()

    def test_attr_iter_pos(self):
        bs = bq.Bstore()
        bs.open(STORE_PATH)
        ai0 = bq.Battr_iter(bs)
        ai1 = bq.Battr_iter(bs)
        attr_types = []
        ai0.first()
        attr_types.append(ai0.obj())
        ai0.next()
        attr_types.append(ai0.obj())
        pos = ai0.get_pos()
        ai1.set_pos(pos)
        self.assertEqual(ai0.obj(), ai1.obj())
        ai1.next()
        attr_types.append(ai1.obj())
        attr_types.sort()
        expect = ["TAG", "ATTR0", "ATTR1"]
        expect.sort()
        self.assertEqual(attr_types, expect)
        del ai0
        del ai1
        bs.close()

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
    unittest.main(failfast=True)
