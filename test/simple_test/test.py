#!/usr/bin/env python

import os
import re
import sys
import time
import shutil
import socket
import logging
import unittest

from test_util.test_util import ts_text, BalerDaemon
from test_util.util import *

from baler import Bq as bq

log = logging.getLogger(__name__)

MAKE_STORE = True

HOST_FILE = "host.list"
HOST_NUM = 16
HOST_ID_BASE = 1000
HOST_RE = re.compile(r"node(\d+)")
HOST2ID = lambda s: HOST_ID_BASE + int(HOST_RE.match(s).groups()[0])
ID2HOST = lambda i: "node%05d" % (i - HOST_ID_BASE)
HOST_LIST = [ "node%05d" % i for i in range(0, 16) ]
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
TS_END = TS_BEGIN + 24*3600
TS_INC = 600

PATTERNS = [
    "This is pattern Zero:",
    "This is pattern One:",
    "This is pattern Two:",
    "This is pattern Three:",
    "This is pattern Four:",
    "This is pattern Five:",
    "This is pattern Six:",
    "This is pattern Seven:",
]

def msg_iter(syslog=False):
    for ts in range(TS_BEGIN, TS_END, TS_INC):
        ttxt = ts_text(ts)
        for h in HOST_LIST:
            for ptn in PATTERNS:
                msg = "%s %s %s %d" % (ttxt, h, ptn, ts)
                if syslog:
                    yield "<1>1 " + msg + "\n"
                else:
                    yield msg

def get_tkn_stat(tkn_str):
    reg = re.compile(r'^.*\W' + tkn_str + '(?:\W+.*)?$')
    count = 0
    for msg in msg_iter():
        if reg.match(msg):
            count += 1
    return count

def get_ptn_stats():
    tokenizer = re.compile("\\w+|\\W")
    ptns = {}
    for p in PATTERNS:
        k = str("<hostname> " + p + ' <dec>')
        m = str(r".* \w+ " + p + r" \d+" )
        assert(k not in ptns)
        ptns[k] = TestPtnEntry(k, m)
    for line in msg_iter():
        ptn = None
        (ts, comp) = parse_hdr(line)
        for (k, e) in ptns.iteritems():
            m = e.regex.match(line)
            if m == None:
                continue
            ptn = e
            e.add_hist(60, ts)
            e.add_hist(3600, ts)
            e.add_comp_hist(60, ts, comp)
            e.add_comp_hist(3600, ts, comp)
            e.count += 1
            tkns = tokenizer.findall(line)
            pos = 0
            for tkn_text in tkns[16:]:
                e.add_ptn_tkn(pos, tkn_text)
                pos += 1
            break
        assert(ptn)
    return ptns

PTN_STAT = get_ptn_stats()
COMP_HIST_TABLE = {}
for (k, e) in PTN_STAT.iteritems():
    COMP_HIST_TABLE.update(e.comp_hist)

def get_ptn_hist(bin_width, start = 0):
    ret = {}
    base = lambda k: k[0] == bin_width
    gt = lambda k: k[1] >= start
    lt = lambda k: k[1] <= start
    if start:
        cond = lambda k: base(k) and gt(k)
    else:
        cond = base
    for (k,e) in PTN_STAT.iteritems():
        hist = { _k:_v for (_k,_v) in e.hist.iteritems() \
                                                    if cond(_k)}
        ret[k] = hist
    return ret

def KV_HEAD(_h, n=10):
    for (k, v) in _h.iteritems():
        print k, ":", v
        n -= 1
        if not n:
            break

def get_tkn_hist(bin_width = 3600, ts_start = 0, tkn_text = None):
    hist = {} # key: bin_width, time, tkn_text, value: count
    tokenizer = re.compile("\\w+|\\W")
    for line in msg_iter():
        ts = parse_local_time(line)
        ts = int(ts) / bin_width * bin_width
        if ts_start:
            if ts < ts_start:
                continue
        tkns = tokenizer.findall(line)
        for tkn in tkns[16:]:
            if tkn_text and tkn_text != tkn:
                continue
            if BTEST_TKN_TYPE_MASK:
                _tkn_type = get_tkn_type(tkn)
                if _tkn_type and (TYPE_MASK(_tkn_type) & BTEST_TKN_TYPE_MASK):
                    continue # skip the masked tokens
            key = (bin_width, ts, tkn)
            try:
                hist[key] += 1
            except KeyError:
                hist[key] = 1
    return hist

class TestSimple(unittest.TestCase):
    """Test baler daemon rerun"""

    @classmethod
    def _make_store(cls):
        shutil.rmtree(STORE_PATH, True)
        # prep host file
        with open(HOST_FILE, "w") as f:
            for i in range(0, HOST_NUM):
                _id = HOST_ID_BASE + i
                name = "node%05d" % i
                print >>f, name, _id
        # prep config file
        with open(CONFIG_FILE, 'w') as f:
            f.write(CONFIG_TEXT)
        # start balerd
        balerd = BalerDaemon(STORE_PATH, config_file = CONFIG_FILE,
                                         log_file = BALERD_LOG,
                                         log_verbosity = "INFO")
        balerd.start()
        # feed data to balerd
        sock = socket.create_connection(("localhost", PORT))
        for msg in msg_iter(syslog=True):
            sock.send(msg)
        sock.close()
        balerd.wait_idle()
        balerd.stop()

        bs = BStore.open("bstore_sos", STORE_PATH, os.O_RDWR, 0)
        cls.tag_base = []
        if not bs.attrFind("TAG"):
            bs.attrNew("TAG")
        if not bs.attrFind("HEX"):
            bs.attrNew("HEX")
        for ptn in PtnIter(bs):
            bs.ptnAttrValueSet(ptn.ptn_id, "HEX", hex(ptn.ptn_id))
            if ptn.ptn_id % 2:
                cls.tag_base.append( (ptn.ptn_id, "TAG", "odd") )
            else:
                cls.tag_base.append( (ptn.ptn_id, "TAG", "even") )
            if ptn.ptn_id % 3 == 0:
                cls.tag_base.append( (ptn.ptn_id, "TAG", "triple") )
        for (ptn_id, attr_type, attr_value) in cls.tag_base:
            try:
                bs.ptnAttrValueAdd(ptn_id, attr_type, attr_value)
            except:
                pass

    @classmethod
    def setUpClass(cls):
        cls.bs = None
        if MAKE_STORE:
            cls._make_store()
        cls.bs = BStore.open("bstore_sos", STORE_PATH, os.O_RDWR, 0)

    @classmethod
    def tearDownClass(cls):
        del cls.bs

    def test_001_msg(self):
        """Check bstore messages"""
        itr = MsgIter(self.bs)
        msgs = [ m.msg() for m in itr ]
        msgs.sort()
        comp = [ s for s in msg_iter() ]
        comp.sort()
        self.assertEqual(msgs, comp)

    def test_tkn(self):
        """Check some token id<->str translation"""
        texts = ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven"]
        for text in texts:
            tkn0 = self.bs.tknFindByName(text)
            tkn1 = self.bs.tknFindById(tkn0.tkn_id)
            # tkn obtained by id and name should be the same.
            self.assertEqual(tkn0.tkn_id, tkn1.tkn_id)
            self.assertEqual(tkn0.tkn_text, tkn1.tkn_text)
            self.assertEqual(tkn0.tkn_count, tkn1.tkn_count)
            self.assertEqual(tkn0.tkn_type_mask, tkn1.tkn_type_mask)

            count = get_tkn_stat(text)
            self.assertEqual(tkn0.tkn_count, count)

    def test_tkn_iter_pos(self):
        """Test tkn_iter_pos"""
        itr0 = TknIter(self.bs)
        itr1 = TknIter(self.bs)
        tkn0 = itr0.first()
        N = 50
        for i in range(0, N):
            tkn0 = itr0.next()
        pos = itr0.get_pos()
        self.assertIsNotNone(pos)
        itr1.set_pos(pos)
        tkn1 = itr1.obj()
        self.assertEqual(tkn0, tkn1)
        count = N
        while count:
            tkn0 = itr0.next()
            tkn1 = itr1.next()
            self.assertEqual(tkn0, tkn1)
            count -= 1
        self.assertEqual(count, 0)

    def test_tkn_iter_card(self):
        """Test tkn_iter_card"""
        itr = TknIter(self.bs)
        itr.first()
        card = itr.card()
        for x in itr:
            card -= 1
        self.assertEqual(card, 0)

    def __test_iter_fwd_rev(self, ItrCls, N, *args, **kwargs):
        itr = ItrCls(self.bs, *args, **kwargs)
        stack = [itr.first()]
        for i in range(0, N):
            stack.append(itr.next())
        stack2 = []
        tkn = itr.obj()
        while tkn:
            stack2.append(tkn)
            # self.assertEqual(tkn, stack.pop())
            tkn = itr.prev()
        stack2.reverse()
        self.assertEqual(stack, stack2)
        # self.assertEqual(len(stack), 0)

    def __test_iter_rev_fwd(self, ItrCls, N, *args, **kwargs):
        itr = ItrCls(self.bs, *args, **kwargs)
        stack = [itr.last()]
        for i in range(0, N):
            stack.append(itr.prev())
        tkn = itr.obj()
        while tkn:
            self.assertEqual(tkn, stack.pop())
            tkn = itr.next()
        self.assertEqual(len(stack), 0)

    def test_ptn_tkn_iter_fwd_rev(self):
        self.__test_iter_fwd_rev(PtnTknIter, 20, 256, 11)
        # no need to do rev-fwd, as PtnTknIter usage is:
        #  - find, then
        #  - next / prev

    def test_tkn_iter_fwd_rev(self):
        self.__test_iter_fwd_rev(TknIter, 20)

    def test_tkn_iter_rev_fwd(self):
        self.__test_iter_rev_fwd(TknIter, 20)

    def test_ptn(self):
        ptns = set()
        for ptn in PtnIter(self.bs):
            e = PTN_STAT[str(ptn)]
            self.assertEqual(ptn.count, e.count)
            ptns.add(str(ptn))
        self.assertEqual(ptns, set(PTN_STAT))

    def test_ptn_pos_obj(self):
        itr1 = PtnIter(self.bs)
        p1 = itr1.first()
        self.assertTrue(p1)
        p1 = itr1.next()
        self.assertTrue(p1)

        pos = itr1.get_pos()
        assert(pos)

        itr2 = PtnIter(self.bs)
        itr2.set_pos(pos)
        p2 = itr2.obj()

        count = 0

        while p1 and p2:
            self.assertEqual(p1, p2)
            count += 1
            p1 = itr1.next()
            p2 = itr2.next()
        self.assertIsNone(p1)
        self.assertIsNone(p2)
        self.assertTrue(count)
        pass

    def test_ptn_iter_fwd_rev(self):
        itr1 = PtnIter(self.bs)
        itr2 = PtnIter(self.bs)
        ptn_list = []
        ptn = itr2.last()
        while ptn:
            ptn_list.append(ptn)
            ptn = itr2.prev()
        ptn_list.reverse()

        count = 0
        for p1, p2 in itertools.izip_longest(ptn_list, iter(itr1)):
            self.assertEqual(p1, p2)
            count += 1
        self.assertTrue(count)
        pass

    def test_ptn_iter_fwd_rev2(self):
        itr = PtnIter(self.bs)
        N = 4
        ptn_list = [itr.first()]
        for i in range(0, N):
            ptn_list.append(itr.next())
        ptn = itr.obj()
        while ptn and ptn_list:
            self.assertEqual(str(ptn), str(ptn_list.pop()))
            ptn = itr.prev()
        self.assertEqual(len(ptn_list), 0)
        self.assertIsNone(ptn)

    def test_ptn_iter_card(self):
        itr = PtnIter(self.bs)
        itr.first()
        card = itr.card()
        count = 0
        for ptn in itr:
            count += 1
        self.assertEqual(count, card)

    def test_ptn_iter_find_fwd(self):
        itr = PtnIter(self.bs)
        ptn_id = 260
        self.assertTrue(itr.find_fwd(ptn_id = ptn_id))
        ptn = itr.obj()
        self.assertEqual(ptn.ptn_id, ptn_id)

    def test_ptn_iter_find_rev(self):
        itr = PtnIter(self.bs)
        ptn_id = 260
        self.assertTrue(itr.find_rev(ptn_id = ptn_id))
        ptn = itr.obj()
        self.assertEqual(ptn.ptn_id, ptn_id)

    def test_ptn_iter_filter(self):
        itr = PtnIter(self.bs)
        ts = TS_BEGIN
        itr.set_filter(tv_begin=(ts, 0))
        count = 0
        for ptn in itr:
            self.assertGreaterEqual(ptn.first_seen, ts)
            count += 1
        self.assertGreater(count, 0)

    def test_ptn_iter_filter_pos(self):
        itr1 = PtnIter(self.bs)
        ts = TS_BEGIN
        itr1.set_filter(tv_begin=(ts, 0))
        ptn1 = itr1.first()
        self.assertIsNotNone(ptn1)
        ptn1 = itr1.next()
        self.assertIsNotNone(ptn1)
        ptn1 = itr1.next()
        self.assertIsNotNone(ptn1)
        pos = itr1.get_pos()
        self.assertIsNotNone(pos)
        itr2 = PtnIter(self.bs)
        itr2.set_pos(pos)
        ptn2 = itr2.obj()
        self.assertTrue(ptn2)
        count = 0
        while ptn1 and ptn2:
            self.assertEqual(ptn1, ptn2)
            ptn1 = itr1.next()
            ptn2 = itr2.next()
            count += 1
        self.assertIsNone(ptn1)
        self.assertIsNone(ptn2)
        self.assertTrue(count)

    def test_ptn_iter_filter_pos_rev(self):
        itr1 = PtnIter(self.bs)
        ts = TS_BEGIN
        itr1.set_filter(tv_begin=(ts, 0))
        ptn1 = itr1.first()
        self.assertIsNotNone(ptn1)
        ptn1 = itr1.next()
        self.assertIsNotNone(ptn1)
        ptn1 = itr1.next()
        self.assertIsNotNone(ptn1)
        pos = itr1.get_pos()
        self.assertIsNotNone(pos)
        itr2 = PtnIter(self.bs)
        itr2.set_pos(pos)
        ptn2 = itr2.obj()
        self.assertTrue(ptn2)
        count = 0
        while ptn1 and ptn2:
            self.assertEqual(ptn1, ptn2)
            ptn1 = itr1.prev()
            ptn2 = itr2.prev()
            count += 1
        self.assertIsNone(ptn1)
        self.assertIsNone(ptn2)
        self.assertTrue(count)

    def test_msg_iter_card(self):
        sum_card = 0
        itr = MsgIter(self.bs)
        itr.first()
        card = itr.card()
        for ptn in PtnIter(self.bs):
            sum_card += ptn.count
        self.assertEqual(card, sum_card)

    def test_msg_iter_fwd(self):
        msgs2 = [m for m in msg_iter()]
        msgs2.sort()
        itr = MsgIter(self.bs)
        msgs1 = []
        for msg in itr:
            host_str = str(msg.host)
            host_check = msg.text().split(" ")[0]
            self.assertEqual(host_str, host_check)
            msgs1.append(msg.msg())
        msgs1.sort()
        self.assertEqual(len(msgs1), len(msgs2))
        self.assertEqual(msgs1, msgs2)

    def test_msg_iter_rev(self):
        global msg_fwd, msg_rev, msg, bs
        bs = self.bs
        msg_fwd = [str(msg) for msg in MsgIter(self.bs)]
        msg_rev = [str(msg) for msg in MsgRevIter(self.bs)]
        self.assertEqual(len(msg_fwd), len(msg_rev))
        for i in range(0, len(msg_fwd)):
            self.assertEqual(msg_fwd[i], msg_rev[-(i+1)])

    def test_msg_iter_fwd_rev(self):
        count = 20
        itr = MsgIter(self.bs)
        stack = [str(itr.first())]
        for i in range(0, count):
            stack.append(str(itr.next()))
        msg = itr.obj()
        while msg:
            m = stack.pop()
            self.assertEqual(m, str(msg))
            msg = itr.prev()
        self.assertEqual(len(stack), 0)

    def test_msg_iter_filter_comp(self):
        name = "node00012"
        reg = re.compile(name)
        msgs0 = []
        msgs1 = list(filter(lambda s: reg.findall(s), msg_iter()))
        comp = self.bs.tknFindByName(name)
        self.assertIsNotNone(comp)
        for msg in MsgIterFilter(self.bs, comp_id=comp.tkn_id):
            self.assertEqual(msg.comp_id, comp.tkn_id)
            msgs0.append(msg.msg())
        msgs0.sort()
        msgs1.sort()
        self.assertGreater(len(msgs0), 0)
        self.assertEqual(msgs0, msgs1)

    def __test_msg_iter_find_pos(self, start, ptn_id, comp):
        comp_id = 0
        if comp:
            comp = self.bs.tknFindByName(comp)
            comp_id = comp.tkn_id
        itr0 = MsgIter(self.bs)
        msg0 = itr0.find_fwd(tv=(start, 0), comp_id=comp_id, ptn_id=ptn_id)
        self.assertIsNotNone(msg0)
        for x in range(0, 4):
            msg0 = itr0.next()
            self.assertIsNotNone(msg0)
        pos0 = itr0.get_pos()
        itr1 = MsgIter(self.bs)
        itr1.set_pos(pos0)
        msg1 = itr1.obj()
        while msg0 and msg1:
            msg0 = itr0.next()
            msg1 = itr1.next()
            self.assertEqual(msg0, msg1)

    def __test_msg_iter_find_pos_rev(self, start, ptn_id, comp):
        comp_id = 0
        if comp:
            comp = self.bs.tknFindByName(comp)
            comp_id = comp.tkn_id
        itr0 = MsgIter(self.bs)
        msg0 = itr0.find_fwd(tv=(start, 0), comp_id=comp_id, ptn_id=ptn_id)
        self.assertIsNotNone(msg0)
        for x in range(0, 4):
            msg0 = itr0.next()
            self.assertIsNotNone(msg0)
        pos0 = itr0.get_pos()
        itr1 = MsgIter(self.bs)
        itr1.set_pos(pos0)
        msg1 = itr1.obj()
        while msg0 and msg1:
            msg0 = itr0.prev()
            msg1 = itr1.prev()
            self.assertEqual(msg0, msg1)

    def test_msg_iter_find_comp_pos(self):
        self.__test_msg_iter_find_pos(0, 0, "node00012")

    def test_msg_iter_find_comp_pos_rev(self):
        self.__test_msg_iter_find_pos_rev(0, 0, "node00012")

    def test_msg_iter_find_comp_time_pos(self):
        self.__test_msg_iter_find_pos(TS_BEGIN + 4*3600, 0, "node00012")

    def test_msg_iter_find_comp_time_pos_rev(self):
        self.__test_msg_iter_find_pos_rev(TS_BEGIN + 4*3600, 0,
                                          "node00012")

    def test_msg_iter_find_time_pos(self):
        self.__test_msg_iter_find_pos(TS_BEGIN + 4*3600, 0, None)

    def test_msg_iter_find_time_pos_rev(self):
        self.__test_msg_iter_find_pos_rev(TS_BEGIN + 4*3600, 0, None)

    def test_msg_iter_find_ptn_pos(self):
        self.__test_msg_iter_find_pos(0, 263, None)

    def test_msg_iter_find_ptn_pos_rev(self):
        self.__test_msg_iter_find_pos_rev(0, 263, None)

    def test_msg_iter_find_ptn_time_pos(self):
        self.__test_msg_iter_find_pos(TS_BEGIN + 4*3600, 263, None)

    def test_msg_iter_find_ptn_time_pos_rev(self):
        self.__test_msg_iter_find_pos_rev(TS_BEGIN + 4*3600, 263, None)

    def test_msg_iter_find_ptn_comp_time_pos(self):
        self.__test_msg_iter_find_pos(TS_BEGIN + 4*3600, 263, "node00012")

    def test_msg_iter_find_ptn_comp_time_pos_rev(self):
        self.__test_msg_iter_find_pos_rev(TS_BEGIN + 4*3600, 263,
                                          "node00012")

    def test_msg_iter_filter_comp_time(self):
        name = "node00012"
        ts = TS_BEGIN + 4*3600
        tv_begin = (ts, 0)
        reg = re.compile(name)
        msgs0 = []
        msgs1 = list(filter(lambda s: reg.findall(s), msg_iter()))
        comp = self.bs.tknFindByName(name)
        self.assertIsNotNone(comp)
        for msg in MsgIterFilter(self.bs, tv_begin=tv_begin,
                                 comp_id=comp.tkn_id):
            self.assertEqual(msg.comp_id, comp.tkn_id)
            msgs0.append(msg.msg())
        msgs0.sort()
        msgs1.sort()
        l = len(msgs1) - len(msgs0)
        self.assertGreater(len(msgs0), 0)
        self.assertEqual(msgs0, msgs1[l:])
        msgs2 = msgs1[:l]
        for msg in msgs2:
            t = parse_local_time(msg)
            self.assertLess(t, ts)

    def test_msg_iter_filter_time(self):
        ts = TS_BEGIN + 4*3600
        tv_begin = (ts, 0)
        msgs0 = [msg.msg() for msg in MsgIterFilter(self.bs, tv_begin=tv_begin)]
        msgs1 = [m for m in msg_iter()]
        msgs0.sort()
        msgs1.sort()
        l = len(msgs1) - len(msgs0)
        self.assertGreater(len(msgs0), 0)
        self.assertEqual(msgs0, msgs1[l:])
        msgs2 = msgs1[:l]
        for msg in msgs2:
            t = parse_local_time(msg)
            self.assertLess(t, ts)

    def test_msg_iter_filter_ptn(self):
        ptn_id = 263
        msgs0 = []
        for msg in MsgIterFilter(self.bs, ptn_id=ptn_id):
            self.assertEqual(msg.ptn_id, ptn_id)
            msgs0.append(msg.msg())
        ptn = self.bs.ptnFindById(ptn_id)
        s = re.match(".*(This is pattern .*):.*", str(ptn)).group(1)
        r = re.compile(s)
        msgs1 = list(filter( lambda x: r.search(x), msg_iter() ))
        msgs0.sort()
        msgs1.sort()
        self.assertGreater(len(msgs0), 0)
        self.assertEqual(msgs0, msgs1)

    def test_msg_iter_filter_ptn_time(self):
        ptn_id = 263
        ts = TS_BEGIN + 4*3600
        tv_begin = (ts, 0)
        msgs0 = []
        for msg in MsgIterFilter(self.bs, ptn_id=ptn_id, tv_begin=tv_begin):
            self.assertEqual(msg.ptn_id, ptn_id)
            msgs0.append(msg.msg())
        ptn = self.bs.ptnFindById(ptn_id)
        s = re.match(".*(This is pattern .*):.*", str(ptn)).group(1)
        r = re.compile(s)
        msgs1 = list(filter( lambda x: r.search(x), msg_iter() ))
        msgs0.sort()
        msgs1.sort()
        l = len(msgs1) - len(msgs0)
        self.assertEqual(msgs0, msgs1[l:])
        self.assertGreater(len(msgs0), 0)
        for msg in msgs1[:l]:
            t = parse_local_time(msg)
            self.assertLess(t, ts)

    def test_msg_iter_filter_ptn_comp_time(self):
        ptn_id = 263
        name = "node00012"
        ts = TS_BEGIN + 4*3600
        tv_begin = (ts, 0)
        node_reg = re.compile(name)
        ptn = self.bs.ptnFindById(ptn_id)
        s = re.match(".*(This is pattern .*):.*", str(ptn)).group(1)
        ptn_reg = re.compile(s)
        comp = self.bs.tknFindByName(name)
        self.assertIsNotNone(comp)

        msgs0 = []
        msgs1 = list(filter(
                        lambda s: node_reg.search(s) and ptn_reg.search(s),
                        msg_iter()))
        for msg in MsgIterFilter(self.bs, ptn_id=ptn_id,
                                 tv_begin=tv_begin, comp_id=comp.tkn_id):
            self.assertEqual(msg.ptn_id, ptn_id)
            msgs0.append(msg.msg())
        msgs0.sort()
        msgs1.sort()
        l = len(msgs1) - len(msgs0)
        self.assertGreater(l, 0)
        self.assertEqual(msgs0, msgs1[l:])
        self.assertGreater(len(msgs0), 0)
        for msg in msgs1[:l]:
            t = parse_local_time(msg)
            self.assertLess(t, ts)

    def test_msg_iter_pos(self):
        n = 10
        limit = 20

        itr0 = MsgIter(self.bs)
        msg0 = itr0.first()
        n -= 1
        while n:
            msg0 = itr0.next()
            n -= 1

        pos = itr0.get_pos()

        itr1 = MsgIter(self.bs)
        itr1.set_pos(pos)
        msg1 = itr1.obj()
        self.assertEqual(msg0, msg1)

        while limit:
            msg0 = itr0.next()
            msg1 = itr1.next()
            self.assertEqual(msg0, msg1)
            limit -= 1

    def test_ptn_tkn_iter(self):
        for ptn in PtnIter(self.bs):
            e = PTN_STAT[str(ptn)]
            set0 = set()
            set1 = set(e.ptn_tkn)
            for tkn_pos in range(0, len(ptn.tkn_list)):
                for ptn_tkn in PtnTknIter(self.bs, ptn.ptn_id, tkn_pos):
                    txt = ptn_tkn.ptn_text()
                    if not txt.strip(): # if txt is plain empty spaces
                        continue
                    key = (tkn_pos, txt)
                    set0.add(key)
                    count = e.ptn_tkn[key]
                    self.assertEqual(count, ptn_tkn.tkn_count)
            self.assertEqual(set0, set1)

    def test_ptn_tkn_iter_obj(self):
        itr = PtnTknIter(self.bs, 257, 0)
        tkn0 = itr.first()
        tkn0 = itr.next()
        tkn0 = itr.next()
        tkn1 = itr.obj()
        self.assertEqual(tkn0, tkn1)

    def test_ptn_tkn_iter_pos(self):
        itr0 = PtnTknIter(self.bs, 256, 0)
        tkn0 = itr0.first()
        tkn0 = itr0.next()
        tkn0 = itr0.next()
        pos = itr0.get_pos()
        itr1 = PtnTknIter(self.bs, 256, 0)
        itr1.set_pos(pos)
        tkn1 = itr1.obj()
        self.assertEqual(tkn0, tkn1)
        while tkn0 and tkn1:
            tkn0 = itr0.next()
            tkn1 = itr1.next()
            self.assertEqual(tkn0, tkn1)

    def __tkn_hist_data(self, bin_width, ts, name):
        bs = self.bs
        data = {}
        tkn_id = 0
        histAssert = self.assertGreaterEqual
        if name:
            tkn = bs.tknFindByName(name)
            if not tkn:
                return data
            tkn_id = tkn.tkn_id
        prev_hist = None
        kwargs = {
            "tkn_id": tkn_id,
            "bin_width": bin_width,
            "tv_begin": (ts, 0)
        }
        itr = TknHistIter(bs, **kwargs)
        for hist in itr:
            if tkn_id:
                self.assertEqual(tkn_id, hist.tkn_id)
            if prev_hist:
                histAssert(hist, prev_hist)
            tkn = bs.tknFindById(hist.tkn_id)
            key = (hist.bin_width, hist.time, str(tkn))
            self.assertNotIn(key, data)
            data[key] = hist.tkn_count
            prev_hist = hist
        return data

    def __test_tkn_hist_fwd_iter(self, bin_width, ts, name):
        d0 = self.__tkn_hist_data(bin_width, ts, name)
        d1 = get_tkn_hist(bin_width, ts, name)
        self.assertGreater(len(d0), 0)
        self.assertEqual(d0, d1)

    def test_tkn_hist_fwd_iter_60(self):
        self.__test_tkn_hist_fwd_iter(60, 0, None)

    def test_tkn_hist_fwd_iter_3600(self):
        self.__test_tkn_hist_fwd_iter(3600, 0, None)

    def test_tkn_hist_fwd_iter_tkn_60(self):
        self.__test_tkn_hist_fwd_iter(60, 0, "Zero")

    def test_tkn_hist_fwd_iter_tkn_3600(self):
        self.__test_tkn_hist_fwd_iter(3600, 0, "Zero")

    def test_tkn_hist_fwd_iter_time_60(self):
        self.__test_tkn_hist_fwd_iter(60, TS_BEGIN + 4*3600, None)

    def test_tkn_hist_fwd_iter_time_3600(self):
        self.__test_tkn_hist_fwd_iter(3600, TS_BEGIN + 4*3600, None)

    def test_tkn_hist_fwd_iter_time_tkn_60(self):
        self.__test_tkn_hist_fwd_iter(60, TS_BEGIN + 4*3600, "Zero")

    def test_tkn_hist_fwd_iter_time_tkn_3600(self):
        self.__test_tkn_hist_fwd_iter(3600, TS_BEGIN + 4*3600, "Zero")

    def test_tkn_hist_obj(self):
        name = "Zero"
        tkn = self.bs.tknFindByName(name)
        itr = TknHistIter(self.bs, tkn_id=tkn.tkn_id, bin_width=3600)
        count = 0
        for x in itr:
            o = itr.obj()
            self.assertEqual(x, o)
            count += 1
        self.assertGreater(count, 0)

    def __test_tkn_hist_pos(self, bin_width, start, tkn_text):
        tkn_id = 0 if not tkn_text else self.bs.tknFindByName(tkn_text).tkn_id
        kwargs = {
            "tkn_id": tkn_id,
            "bin_width": bin_width,
            "tv_begin": (start, 0),
        }
        itr1 = TknHistIter(self.bs, **kwargs)
        itr1.first()
        itr1.next()
        itr1.next()
        itr1.next()
        itr1.next()
        pos = itr1.get_pos()
        itr2 = TknHistIter(self.bs, **kwargs)
        itr2.set_pos(pos)
        obj1 = itr1.obj()
        obj2 = itr2.obj()
        self.assertIsNotNone(obj1)
        self.assertIsNotNone(obj2)
        self.assertEqual(obj1, obj2)
        while obj1 and obj2:
            obj1 = itr1.next()
            obj2 = itr2.next()
            self.assertEqual(obj1, obj2)

    def test_tkn_hist_pos(self):
        self.__test_tkn_hist_pos(3600, 0, "Zero")

    def test_tkn_hist_time_pos(self):
        self.__test_tkn_hist_pos(3600, TS_BEGIN + 4*3600, "Zero")

    def __ptn_hist_data(self, bin_width, start = 0):
        data = {}
        for ptn in PtnIter(self.bs):
            pdata = {}
            kwargs = {
                "ptn_id": ptn.ptn_id,
                "bin_width": bin_width,
                "tv_begin": (start, 0),
            }
            for hist in PtnHistIter(self.bs, **kwargs):
                key = (hist.bin_width, hist.time)
                self.assertNotIn(key, pdata)
                pdata[key] = hist.msg_count
            key = str(ptn)
            self.assertFalse(key in data)
            data[key] = pdata
        return data

    def __test_ptn_hist_iter(self, bin_width, ts=0):
        d0 = self.__ptn_hist_data(bin_width, ts)
        d1 = get_ptn_hist(bin_width, ts)
        if False:
            # Debug print
            print "----------------------"
            print "len(d0):", len(d0)
            print "len(d1):", len(d1)
            print "-------  D0  ---------"
            KV_HEAD(d0)
            print "----------------------"
            print "-------  D1  ---------"
            KV_HEAD(d1)
            print "----------------------"
        self.assertEqual(d0, d1)

    def test_ptn_hist_fwd_iter_3600(self):
        self.__test_ptn_hist_iter(3600, 0)

    def test_ptn_hist_fwd_iter_60(self):
        self.__test_ptn_hist_iter(60, 0)

    def test_ptn_hist_fwd_iter_time_3600(self):
        self.__test_ptn_hist_iter(3600, TS_BEGIN + 4*3600)

    def test_ptn_hist_fwd_iter_time_60(self):
        self.__test_ptn_hist_iter(60, TS_BEGIN + 4*3600)

    def __test_ptn_hist_iter_pos(self, bin_width, time, ptn_id):
        kwargs = {
            "ptn_id": ptn_id,
            "bin_width": bin_width,
            "tv_begin": (time, 0),
        }
        itr1 = PtnHistIter(self.bs, **kwargs)
        itr1.first()
        itr1.next()
        itr1.next()
        itr1.next()
        itr1.next()
        pos = itr1.get_pos()
        itr2 = PtnHistIter(self.bs, **kwargs)
        itr2.set_pos(pos)
        obj1 = itr1.obj()
        obj2 = itr2.obj()
        self.assertIsNotNone(obj1)
        while obj1 and obj2:
            self.assertEqual(obj1, obj2)
            obj1 = itr1.next()
            obj2 = itr2.next()
        self.assertEqual(obj1, obj2)

    def test_ptn_hist_iter_pos(self):
        _width = [60, 3600]
        _ptn_id = [0, 263]
        _time = [0, TS_BEGIN + 4*3600]
        for (bw, pid, ts) in itertools.product(_width, _ptn_id, _time):
            self.__test_ptn_hist_iter_pos(bw, ts, pid)

    def __test_comp_hist_iter(self, bin_width, ts, comp_str, ptn_id):
        comp_id = self.bs.tknFindByName(comp_str).tkn_id if comp_str else 0
        ptn_str = str(self.bs.ptnFindById(ptn_id)) if ptn_id else None
        a = {}
        for (k,v) in COMP_HIST_TABLE.iteritems():
            if k[0] != bin_width:
                continue
            if ts and k[1] < ts:
                continue
            if comp_str and k[2] != comp_str:
                continue
            if ptn_str and k[3] != ptn_str:
                continue
            a[k] = v
        try:
            b = {}
            kwargs = {
                "bin_width": bin_width,
                "tv_begin": (ts, 0),
                "comp_id": comp_id,
                "ptn_id": ptn_id
            }
            itr = CompHistIter(self.bs, **kwargs)
            for h in itr:
                c_str = str(self.bs.tknFindById(h.comp_id))
                p_str = str(self.bs.ptnFindById(h.ptn_id))
                k = (h.bin_width, h.time, c_str, p_str)
                self.assertEqual(h.bin_width, bin_width)
                if ts:
                    self.assertGreaterEqual(h.time, ts)
                self.assertTrue(k not in b)
                b[k] = h.msg_count
            self.assertGreater(len(a), 0)
            self.assertEqual(a, b)
        except:
            print ""
            print "bin_width:", bin_width
            print "ts:", ts
            print "comp_id:", comp_id
            print "ptn_id:", ptn_id
            print "len(a):", len(a)
            print "len(b):", len(b)
            print "-- head a--"
            KV_HEAD(a)
            print "-- head b --"
            KV_HEAD(b)
            # print "b:", b
            raise

    def test_comp_hist_iter_3600(self):
        self.__test_comp_hist_iter(3600, 0, None, 0)

    def test_comp_hist_iter_60(self):
        self.__test_comp_hist_iter(60, 0, None, 0)

    def test_comp_hist_iter_3600_ts(self):
        self.__test_comp_hist_iter(3600, TS_BEGIN + 4*3600,
                                    None, 0)

    def test_comp_hist_iter_60_ts(self):
        self.__test_comp_hist_iter(60, TS_BEGIN + 4*3600,
                                    None, 0)

    def test_comp_hist_iter_3600_ts_comp(self):
        self.__test_comp_hist_iter(3600, TS_BEGIN + 4*3600,
                                    "node00001", 0)

    def test_comp_hist_iter_60_ts_comp(self):
        self.__test_comp_hist_iter(60, TS_BEGIN + 4*3600,
                                    None, 256)

    def test_comp_hist_iter_3600_ts_ptn(self):
        self.__test_comp_hist_iter(3600, TS_BEGIN + 4*3600,
                                    "node00001", 0)

    def test_comp_hist_iter_60_ts_ptn(self):
        self.__test_comp_hist_iter(60, TS_BEGIN + 4*3600,
                                    None, 256)

    def test_comp_hist_iter_3600_ts_comp_ptn(self):
        self.__test_comp_hist_iter(3600, TS_BEGIN + 4*3600,
                                    "node00001", 256)

    def test_comp_hist_iter_60_ts_comp_ptn(self):
        self.__test_comp_hist_iter(60, TS_BEGIN + 4*3600,
                                    "node00001", 256)

    def __test_comp_hist_iter_pos(self, bin_width, time, comp, ptn_id):
        comp_id = 0 if not comp else self.bs.tknFindByName(comp).tkn_id
        kwargs = {
            "bin_width": bin_width,
            "tv_begin": (time, 0),
            "comp_id": comp_id,
            "ptn_id": ptn_id
        }
        itr1 = CompHistIter(self.bs, **kwargs)
        itr1.first()
        itr1.next()
        itr1.next()
        itr1.next()
        itr1.next()
        pos = itr1.get_pos()
        itr2 = CompHistIter(self.bs, **kwargs)
        itr2.set_pos(pos)
        obj1 = itr1.obj()
        obj2 = itr2.obj()
        self.assertIsNotNone(obj1)
        while obj1 and obj2:
            self.assertEqual(obj1, obj2)
            obj1 = itr1.next()
            obj2 = itr2.next()
        self.assertEqual(obj1, obj2)

    def test_comp_hist_iter_pos(self):
        _width = [60, 3600]
        _ptn_id = [0, 263]
        _comp = [None, "node00012"]
        _time = [0, TS_BEGIN + 4*3600]
        for (bw, comp, pid, ts) in \
                        itertools.product(_width, _comp, _ptn_id, _time):
            self.__test_comp_hist_iter_pos(bw, ts, comp, pid)

    def test_ptn_attr(self):
        self.assertTrue(self.bs.attrFind("HEX"))
        with self.assertRaises(ValueError):
            self.bs.attrNew("HEX")
        for ptn in PtnIter(self.bs):
            attr_value = self.bs.ptnAttrGet(ptn.ptn_id, "HEX")
            self.assertEqual(attr_value, hex(ptn.ptn_id))
        # also try setting a new value
        self.bs.ptnAttrValueSet(257, "HEX", str(0))
        self.assertEqual(self.bs.ptnAttrGet(257, "HEX"), str(0))

        # set it back
        self.bs.ptnAttrValueSet(257, "HEX", hex(257))
        self.assertEqual(self.bs.ptnAttrGet(257, "HEX"), hex(257))

    def test_ptn_attr_case_1(self):
        # (ptn_id, attr_tyoe) |-> ( (value), ... )
        itr = PtnAttrIter(self.bs)
        itr.set_filter( ptn_id = 258, attr_type = "TAG" )
        tags = [ ent.attr_value for ent in itr ]
        tags.sort()
        self.assertEqual(tags, ["even", "triple"])

    def test_ptn_attr_case_2(self):
        # (ptn_id) |-> ( (type, value), ... )
        itr = PtnAttrIter(self.bs)
        itr.set_filter( ptn_id = 258)
        tvs = [ (ent.attr_type, ent.attr_value) for ent in itr ]
        tvs.sort()
        self.assertEqual(tvs, [
                            ("HEX", hex(long(258))),
                            ("TAG", "even"),
                            ("TAG", "triple"),
                        ])

    def test_ptn_attr_case_3(self):
        # (type) |-> ( (ptn_id, value), ... )
        itr = PtnAttrIter(self.bs)
        itr.set_filter( attr_type = "TAG" )
        cmpr = [ (ent.ptn_id, ent.attr_type, ent.attr_value) for ent in itr ]
        self.tag_base.sort()
        cmpr.sort()
        self.assertEqual(cmpr, self.tag_base)

    def test_ptn_attr_case_4(self):
        # (type, value) |-> ( (ptn_id), ... )
        itr = PtnAttrIter(self.bs)
        itr.set_filter( attr_type = "TAG", attr_value = "triple" )
        cmpr = [ ent.ptn_id for ent in itr ]
        base = [ x[0] for x in self.tag_base if x[2] == "triple" ]
        cmpr.sort()
        base.sort()
        self.assertGreater(len(cmpr), 0)
        self.assertEqual(cmpr, base)

    def test_ptn_attr_add_rm(self):
        self.bs.ptnAttrValueAdd(258, "TAG", "rm_me")
        itr = PtnAttrIter(self.bs)
        itr.set_filter( ptn_id = 258, attr_type = "TAG" )
        tags = [ e.attr_value for e in itr ]
        tags.sort()
        self.assertEqual(tags, ["even", "rm_me", "triple"])

        self.bs.ptnAttrValueRm(258, "TAG", "rm_me")
        itr = PtnAttrIter(self.bs)
        itr.set_filter( ptn_id = 258, attr_type = "TAG" )
        tags = [ e.attr_value for e in itr ]
        tags.sort()
        self.assertEqual(tags, ["even", "triple"])

    def test_msg_iter_count(self):
        itr = MsgIter(self.bs)
        c_all = 0
        c_256 = 0
        c_4ts = 0
        for m in itr:
            c_all += 1
            if m.ptn_id == 256:
                c_256 += 1
            if m.timestamp < TS_BEGIN + 4*TS_INC:
                c_4ts += 1
        ic_all = itr.count(1)
        ic_256 = itr.count(256)
        ic_4ts = itr.count(0, end_time = (TS_BEGIN + 4*TS_INC))

        self.assertEqual(c_all, ic_all)
        self.assertEqual(c_256, ic_256)
        self.assertEqual(c_4ts, ic_4ts)


if __name__ == "__main__":
    LOGFMT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
    DATEFMT = "%F %T"
    logging.basicConfig(format=LOGFMT, datefmt=DATEFMT)
    log.setLevel(logging.INFO)
    # unittest.TestLoader.testMethodPrefix = "test_"
    MAKE_STORE = True
    unittest.main(verbosity=2, failfast=1)
