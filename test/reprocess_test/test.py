#!/usr/bin/env python3

# Test the parallel reprocess capability. The reprocessing program will run in
# parallel to balerd. The test script uses `btkn_add` CLI command to add a new
# WORD, and # `breprocess` CLI command to reprocess.
#
# Scenario:
#
# 0) Start balerd and feed the first set of logs
# 1) Verify results
# 2) Start a re-processing process, and
# 3) feed the second set of logs
# 4) Wait for re-processing process to finish and balerd to be inactive
# 5) Verify the result

import os
import re
import pdb
import sys
import time
import fcntl
import select
import shutil
import socket
import logging
import unittest
import threading
import subprocess as sp

from io import StringIO
from test_util.test_util import ts_text, make_store, BalerDaemon, \
                                send_log_messages

from baler import Bq as bq

STORE_PATH = "./store"
TS_BEGIN = int(time.time()) // (24*3600) * (24*3600)
TS_END = TS_BEGIN + 24*3600
TS_INC = 600
TS_LAST = None
HOST_NUM = 8
HOST_BASE = 1000
HOST_PATH = "./host.list"
DEBUG = True

def HOSTS(rng_flag = 0x3):
    rng_table = {
            0x1: range(0, HOST_NUM//2),
            0x2: range(HOST_NUM//2, HOST_NUM),
            0x3: range(0, HOST_NUM),
        }
    rng = rng_table[rng_flag]
    for num in rng:
        yield ("host%05d" % num, HOST_BASE + num)

def HOST_ID_ENTRIES():
    for num in range(0, HOST_NUM):
        yield "host%05d %d" % (num, HOST_BASE + num)

def make_host_list():
    f = open(HOST_PATH, "w")
    for l in HOST_ID_ENTRIES():
        print(l, file=f)
    f.close()

time.tzset()

def str_findall(needle, haystack):
    coll = []
    pos = haystack.find(needle)
    while pos > 0:
        coll.append(pos)
        pos = haystack.find(needle, pos+1)
    return coll

def TS_RANGE():
    for ts in range(TS_BEGIN, TS_END, TS_INC):
        yield ts_text(ts)

class Msg(object):
    __slots__ = ["ts", "ts_text", "host", "body_text"]
    def __init__(self, ts, ts_text, host, body_text):
        self.ts = ts
        self.ts_text = ts_text
        self.host = host
        self.body_text = body_text

    def __str__(self):
        return self.ts_text + " " + self.host + " " + self.body_text

    def sock_msg(self):
        return "<1>1 " + str(self) + "\n"

    def host_msg(self):
        """<host> + <body_text>"""
        return self.host + " " + self.body_text

# templates for constructing messages
TEMPLATES = [
    "{lol} Zero + Pattern + Zero: {num}",
    "{lol} One + Pattern + One: {num}",
    "{lol} Two + Two + Pattern + Two + Two: {num}",
    "{lol} Three + Pattern + Three: {num}",
    "{lol} Four + Pattern + Four: {num}",
    "{lol} Five + Pattern + Five: {num}",
    "{lol} Six + Pattern + Six: {num}",
    "{lol} Seven + Pattern + Seven: {num}",
    #"Internationalization + Internationalization + Internationalization + Pattern + Internationalization:",
]
NPTNS = len(TEMPLATES)

to_ptn_0 = lambda tmp: "<host> " + tmp.format(lol="<svc>", num="<dec>")
to_ptn_1 = lambda tmp: "<host> " + tmp.format(lol="LOL", num="<dec>")

FIRST_PTN_ID = 256
# expected patterns before `LOL` is known
PATTERNS_0 = [ to_ptn_0(t) for t in TEMPLATES ]
PTN_IDS_0 = [ FIRST_PTN_ID + i for i in range(0, NPTNS) ]

# expected patterns after `LOL` is known
PATTERNS_1 = [ to_ptn_1(t) for t in TEMPLATES ]
PTN_IDS_1 = [ FIRST_PTN_ID + NPTNS + i for i in range(0, NPTNS) ]

TO_PTN_ID_1 = { _id0: _id1 for _id0, _id1 in zip(PTN_IDS_0, PTN_IDS_1) }
TO_PTN_ID_1[1] = 1
TO_PTN_ID_1.update( (_id1, _id1) for _id1 in PTN_IDS_1 )
to_ptn_id_1 = lambda _id: TO_PTN_ID_1[_id]

MSG_COUNT = 0
PTN_0_COUNT = { ptn: 0 for ptn in PATTERNS_0 }
PTN_0_LAST_SEEN = { ptn: 0 for ptn in PATTERNS_0 }
PTN_0_FIRST_SEEN = { ptn: float('inf') for ptn in PATTERNS_0 }
PTN_1_COUNT = { ptn: 0 for ptn in PATTERNS_1 + PATTERNS_0 }
PTN_1_LAST_SEEN = { ptn: 0 for ptn in PATTERNS_1 }
PTN_1_FIRST_SEEN = { ptn: float('inf') for ptn in PATTERNS_1 }

PTN_HIST = dict() # key: (bin, ts, ptn_id), value: count
COMP_HIST = dict() # key: (bin, ts, comp_id, ptn_id), value: count

def ptn_first_seen(ptn_idx):
    return TS_BEGIN + ptn_idx * TS_INC

def ptn_last_seen(ptn_idx):
    return TS_END - (len(TEMPLATES) - ptn_idx ) * TS_INC

def inc(_d, _k, _v = 1):
    """Increase `_d[_k]` by `_v`"""
    _d[_k] = _d.get(_k, 0) + _v

def add_hist(ts, ptn_id, comp_id):
    for _bin in (60, 3600, 86400):
        _ts = int(ts // _bin) * _bin
        inc(PTN_HIST, (_bin, _ts, ptn_id), 1)
        inc(PTN_HIST, (_bin, _ts, 1), 1) # the sum
        inc(COMP_HIST, (_bin, _ts, comp_id, ptn_id), 1)

def MESSAGES(count = False, host_rng_flag = 0x3):
    global MSG_COUNT
    global PTN_0_COUNT, PTN_1_COUNT
    global PTN_0_FIRST_SEEN, PTN_1_FIRST_SEEN
    global PTN_0_LAST_SEEN, PTN_1_LAST_SEEN
    ts_count = int(TS_END - TS_BEGIN + TS_INC - 1) // TS_INC
    ptn_count = len(TEMPLATES)
    for ts in range(TS_BEGIN, TS_END, TS_INC):
        _ts_text = ts_text(ts)
        for h, comp_id in HOSTS(host_rng_flag):
            ptn_idx = -1
            for tmp in TEMPLATES:
                ptn_idx += 1
                if ts < ptn_first_seen(ptn_idx) or ptn_last_seen(ptn_idx) < ts:
                    continue
                msg = tmp.format(lol="LOL", num=(ts + comp_id))
                yield Msg(ts, _ts_text, h, msg)
                if count:
                    ptn_0 = PATTERNS_0[ptn_idx]
                    ptn_1 = PATTERNS_1[ptn_idx]
                    MSG_COUNT += 1
                    PTN_0_FIRST_SEEN[ptn_0] = min(PTN_0_FIRST_SEEN[ptn_0], ts)
                    PTN_1_FIRST_SEEN[ptn_1] = min(PTN_1_FIRST_SEEN[ptn_1], ts)
                    PTN_0_LAST_SEEN[ptn_0]  = max(PTN_0_LAST_SEEN[ptn_0],  ts)
                    PTN_1_LAST_SEEN[ptn_1]  = max(PTN_1_LAST_SEEN[ptn_1],  ts)
                    # hist
                    if host_rng_flag & 0x1: # first half
                        ptn_id = PTN_IDS_0[ptn_idx]
                        PTN_0_COUNT[ptn_0] += 1
                    if host_rng_flag & 0x2: # second half
                        ptn_id = PTN_IDS_1[ptn_idx]
                        PTN_1_COUNT[ptn_1] += 1
                    add_hist(ts, ptn_id, comp_id)


def MESSAGES_FIRST_HALF(count = False):
    for m in MESSAGES(count = count, host_rng_flag = 0x1):
        yield m

def MESSAGES_SECOND_HALF(count = False):
    for m in MESSAGES(count = count, host_rng_flag = 0x2):
        yield m

log = logging.getLogger(__name__)

class Debug(object): pass

D = Debug()

_bs = None
def get_bstore():
    global _bs
    if _bs:
        return _bs
    try:
        _bs = bq.Bstore()
        _bs.open(STORE_PATH)
    except:
        _bs = None
        raise # continue raising the exception
    return _bs

def bs_hist(hist_type, bin_width = 60, **kwargs):
    bs = get_bstore()
    table = {
        "tkn": bq.Btkn_hist_iter,
        "ptn": bq.Bptn_hist_iter,
        "comp": bq.Bcomp_hist_iter,
    }
    itr = table[hist_type](bs)
    itr.set_filter(bin_width = bin_width, **kwargs)
    ents = [ h for h in itr ]
    D.bsents = ents
    return ents

def cmd(*args, in_data=None, timeout=None):
    _cmd = ' '.join(args)
    p = sp.Popen(_cmd, shell=True, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.STDOUT)
    (out, err) = p.communicate(input=in_data, timeout=timeout)
    return out

DATE_FMT = r'\d\d\d\d-\d\d-\d\d'
TIME_FMT = r'\d\d:\d\d:\d\d'

UND = '\x1b[4m'
RST = '\x1b[0m'


def parse_bq_ptn_tkn(l, cwidths):
    sio = StringIO(l)
    tkns = list()
    for w in cwidths:
        tkns.append(sio.read(w).strip())
        sio.read(1)
    return tkns


def get_matched_ptns(bs, token):
    """Get patterns matching the token"""
    ptns = []
    for ptn in bq.Bptn_iter(bs):
        pos = 0
        matched = [] # will store matched positions
        for tkn in ptn:
            _set = set( str(t) for t in bq.Bptn_tkn_iter(bs,
                                            ptn_id = ptn.ptn_id(),
                                            tkn_pos = pos) )
            _set.add(str(tkn))
            if token in _set:
                matched.append(pos)
            pos += 1
        if matched:
            ptns.append((ptn, matched))
    return ptns


class TestReprocess(unittest.TestCase):
    balerd = None
    @classmethod
    def setUpClass(cls):
        log.info("------- setUpClass -------")
        shutil.rmtree(STORE_PATH, ignore_errors = True)
        make_host_list()
        balerd_cfg = """
            tokens type=HOSTNAME path={host_path}
            tokens type=WORD path=test_util/eng-dictionary
            plugin name=bout_store_msg
            plugin name=bout_store_hist tkn=1 ptn=1 ptn_tkn=1
            plugin name=bin_tcp port=10514 parser=syslog_parser
        """.format(
                host_path = HOST_PATH
            )
        cls.balerd = BalerDaemon(STORE_PATH, config_text = balerd_cfg)
        cls.balerd.start()
        send_log_messages(map(lambda m: m.sock_msg(), MESSAGES_FIRST_HALF(count=True)))
        cls.balerd.wait_idle()
        log.info("------- setUpClass COMPLETED -------")

    @classmethod
    def tearDownClass(cls):
        log.info("------- tearDownClass -------")

    def test_001_verify_patterns(self):
        """Verify patterns (before reprocess)"""
        bs = get_bstore()
        pitr = bq.Bptn_iter(bs)
        bs_ptns = set( str(p) for p in pitr )
        exp_ptns = set(PATTERNS_0)
        self.assertEqual(bs_ptns, exp_ptns)

    def test_002_verify_pattern_hist(self):
        """Verify pattern hist (before reprocess)"""
        bs = get_bstore()
        exp = [ k + (v,) for k, v in PTN_HIST.items() ]
        ph = [ tuple(p) for p in bq.Bptn_hist_iter(bs) ]
        exp.sort()
        ph.sort()
        self.assertTrue(ph == exp)

    def test_003_verify_comp_hist(self):
        """Verify comp hist (before reprocess)"""
        bs = get_bstore()
        exp = [ k + (v,) for k, v in COMP_HIST.items() ]
        ch = [ tuple(c) for c in bq.Bcomp_hist_iter(bs) ]
        exp.sort()
        ch.sort()
        self.assertTrue(ch == exp)

    def test_004_verify_ptn_first_seen(self):
        """Verify ptn first seen (before reprocess)"""
        bs = get_bstore()
        ptns = [ p for p in bq.Bptn_iter(bs) ]
        first_seen = { str(p): p.first_seen() for p in ptns }
        self.assertTrue( first_seen == PTN_0_FIRST_SEEN )

    def test_005_verify_ptn_last_seen(self):
        """Verify ptn last seen (before reprocess)"""
        bs = get_bstore()
        ptns = [ p for p in bq.Bptn_iter(bs) ]
        last_seen = { str(p): p.last_seen() for p in ptns }
        self.assertTrue( last_seen == PTN_0_LAST_SEEN )

    def test_006_update_LOL(self):
        """Add `LOL` word token to the store"""
        bs = get_bstore()
        out = cmd("btkn_add", "-p", STORE_PATH, in_data=b"LOL WORD\n")
        tkn = bs.tkn_by_name("LOL")
        self.assertIsNotNone(tkn)
        self.assertTrue(tkn.has_type(bq.BTKN_TYPE_WORD))

    def test_007_reprocess_while_feeding_new_data(self):
        """Reprocess while feeding new data"""
        # Feed new data using another thread
        global MSG_COUNT
        bs = get_bstore()
        msg_generator = map(lambda m: m.sock_msg(), MESSAGES_SECOND_HALF(count=True))
        t = threading.Thread(target = send_log_messages, args = [msg_generator])
        t.start()
        out = cmd("breprocess", "-p", STORE_PATH)
        t.join()
        py_msgs = [ str(m) for m in MESSAGES() ]
        py_msgs.sort()
        bs_msgs = [ str(m) for m in bq.Bmsg_iter(bs) ]
        bs_msgs.sort()
        self.assertTrue(py_msgs == bs_msgs)

    def test_008_verify_patterns(self):
        """Verify patterns after reprocessing"""
        bs = get_bstore()
        pitr = bq.Bptn_iter(bs)
        bs_ptns = { p.ptn_id(): str(p) for p in pitr }
        exp_ptns = { _id: _text for _id, _text in zip(PTN_IDS_0 + PTN_IDS_1,
                                                      PATTERNS_0 + PATTERNS_1) }
        self.assertEqual(bs_ptns, exp_ptns)

    def test_009_verify_pattern_count(self):
        """Verify pattern message count after reprocessing"""
        bs = get_bstore()
        pitr = bq.Bptn_iter(bs)
        bs_ptns = { str(p): p.msg_count() for p in pitr }
        # expect 0 message count for all PATTERNS_0 (old), and the sum of
        # old + new messages in PATTERNS_1.
        py_ptns = { str(p): 0 for p in PATTERNS_0 }
        for t in TEMPLATES:
            p0 = to_ptn_0(t)
            p1 = to_ptn_1(t)
            # PTN_0_COUNT counts first half, PTN_1_COUNT counts second half
            c = PTN_0_COUNT[p0] + PTN_1_COUNT[p1]
            py_ptns[p1] = c
        self.assertTrue(bs_ptns == py_ptns)

    def test_010_verify_pattern_first_seen(self):
        """Verify pattern first seen after reprocessing"""
        bs = get_bstore()
        pitr = bq.Bptn_iter(bs)
        bs_ptns = { str(p): p.first_seen() for p in pitr }
        py_ptns = dict(PTN_0_FIRST_SEEN)
        py_ptns.update(PTN_1_FIRST_SEEN)
        self.assertTrue(bs_ptns == py_ptns)

    def test_011_verify_pattern_last_seen(self):
        """Verify pattern last seen after reprocessing"""
        bs = get_bstore()
        pitr = bq.Bptn_iter(bs)
        bs_ptns = { str(p): p.last_seen() for p in pitr }
        py_ptns = dict(PTN_0_LAST_SEEN)
        py_ptns.update(PTN_1_LAST_SEEN)
        self.assertTrue(bs_ptns == py_ptns)

    def test_012_verify_ptn_hist(self):
        """Verify pattern hist after reprocessing"""
        bs = get_bstore()
        bs_hist = [ tuple(p) for p in bq.Bptn_hist_iter(bs) ]
        py_hist = dict()
        for (_b, _t, _p), n in PTN_HIST.items():
            _k = (_b, _t, to_ptn_id_1(_p))
            try:
                py_hist[_k] += n
            except:
                py_hist[_k] = n
        py_hist = [ k + (v,) for k,v in py_hist.items() ]
        py_hist.sort()
        bs_hist.sort()
        self.assertTrue(py_hist == bs_hist)

    def test_013_verify_comp_hist(self):
        """Verify comp hist after reprocessing"""
        bs = get_bstore()
        bs_hist = [ tuple(p) for p in bq.Bcomp_hist_iter(bs) ]
        py_hist = dict()
        for (_b, _t, _c, _p), n in COMP_HIST.items():
            _k = (_b, _t, _c, to_ptn_id_1(_p))
            try:
                py_hist[_k] += n
            except:
                py_hist[_k] = n
        py_hist = [ k + (v,) for k,v in py_hist.items() ]
        py_hist.sort()
        bs_hist.sort()
        self.assertTrue(py_hist == bs_hist)


def debugResult(fn):
    """Intercept test results in pdb in the case of errors and failures"""
    def interpose(r, test, err):
        pdb.post_mortem(t = err[2])
        fn(r, test, err)
    setattr(unittest.TextTestResult, fn.__name__, interpose)

if __name__ == "__main__":
    pystartup = os.getenv("PYTHONSTARTUP")
    if pystartup:
        execfile(pystartup)
    LOGFMT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
    DATEFMT = "%F %T"
    logging.basicConfig(format=LOGFMT, datefmt=DATEFMT)
    log.setLevel(logging.INFO)
    if DEBUG:
        debugResult(unittest.TextTestResult.addError)
        debugResult(unittest.TextTestResult.addFailure)
    unittest.main(verbosity = 2, failfast = True)
