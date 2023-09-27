#!/usr/bin/env python3
#
# Test basic bstore functionality
#
# For `bstore_sos`: set the BSTORE_PLUGIN variable to 'bstore_sos'. The
# STORE_PATH variable is the path to the store directory.
#
# For 'bstore_dsos': set the BSTORE_PLUGIN variable to 'bstore_dsos' and
# edit STORE_PATH variable and 'dsos.conf' file appropriately. Please make sure
# that the '{STORE_PATH}' exist on the dsos server.

import os
import re
import sys
import pdb
import time
import shutil
import socket
import string
import logging
import unittest

from datetime import datetime

from test_util.test_util import ts_text, BalerDaemon
from test_util.util import *

from baler import Bq as bq

log = logging.getLogger(__name__)

MAKE_STORE = True

BSTORE_PLUGIN = 'bstore_dsos'
os.environ['BALERD_SESSION_FILE'] = 'dsos.conf'
HOST_FILE = "host.list"
DICT_FILE = "eng-dictionary-small"
HOST_NUM = 8
HOST_ID_BASE = 1000
HOST_RE = re.compile(r"node(\d+)")
HOST2ID = lambda s: HOST_ID_BASE + int(HOST_RE.match(s).groups()[0])
ID2HOST = lambda i: "node%05d" % (i - HOST_ID_BASE)
HOST_LIST = [ "node%05d" % i for i in range(0, HOST_NUM) ]
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
STORE_PATH = "/store/test" if BSTORE_PLUGIN == 'bstore_dsos' else "store"
BALERD_LOG = "balerd.log"
TS_BEGIN = 1531785600
TS_END = TS_BEGIN + 4*3600
TS_INC = 3600

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

B_PATTERNS = [ f"<host> {p} <dec>" for p in PATTERNS ]

def messages():
    "Message generator (text)"
    for ts in range(TS_BEGIN, TS_END, TS_INC):
        for host in HOST_LIST:
            for p in PATTERNS:
                d = datetime.fromtimestamp(ts)
                dts = d.astimezone().isoformat()
                msg = f"{p} {ts}"
                full_msg = f"{dts} {host} {msg}"
                yield (ts, host, msg, full_msg)

class GlobalVault(object):
    pass

G = GlobalVault()

class TestBstore(unittest.TestCase):
    """Test Bq.Bstore interface"""

    failureException = Exception

    @classmethod
    def setUpClass(cls):
        if BSTORE_PLUGIN == "bstore_sos":
            shutil.rmtree(STORE_PATH, True)
        G.opened = False

    @classmethod
    def tearDownClass(cls):
        if G.opened:
            G.bs.close()

    def test_001_create_store(self):
        """Check bstore messages"""
        G.bs = bs = Bq.Bstore(plugin = BSTORE_PLUGIN)
        bs.open(STORE_PATH, Bq.O_RDWR|Bq.O_CREAT, 0o660)
        G.opened = True
        self.assertTrue(True)

    def __add_tkn(self, text, type_mask, _id = None):
        tkn = G.bs.tkn_add(text, type_mask, _id)
        G.word_map[text] = tkn.tkn_id()
        G.tkn_id_set.add(tkn.tkn_id())

    def test_002_load_dict(self):
        """Load dictionary"""
        bs = G.bs
        G.word_map = dict()
        G.tkn_id_set = set()
        _HOST = Bq.BTKN_TYPE_MASK(Bq.BTKN_TYPE_HOSTNAME)
        _WORD = Bq.BTKN_TYPE_MASK(Bq.BTKN_TYPE_WORD)
        _WS   = Bq.BTKN_TYPE_MASK(Bq.BTKN_TYPE_WHITESPACE)
        _SEP  = Bq.BTKN_TYPE_MASK(Bq.BTKN_TYPE_SEPARATOR)

        # spaces
        for s in string.whitespace:
            if s == '\0':
                continue # skip NULL byte
            self.__add_tkn(s, _WS)

        # separators
        for p in string.punctuation:
            self.__add_tkn(p, _SEP)

        # host list first
        for h in HOST_LIST:
            _id = HOST2ID(h)
            self.__add_tkn(h, _HOST, _id)

        # then the words
        with open(DICT_FILE) as f:
            for l in f:
                self.__add_tkn(l.strip(), _WORD)
        self.assertTrue(len(G.word_map) == len(G.tkn_id_set))

    def test_003_verify_dict(self):
        """Verify dictionary"""
        bs = G.bs
        for k, v in G.word_map.items():
            tkn = G.bs.tkn_by_name(k)
            self.assertTrue(tkn.tkn_id() == v)

    def test_004_msg_add(self):
        bs = G.bs
        G.bmsgs = list()
        G.ptn_tkns = dict()
        for ts, host, msg, full_msg in messages():
            bmsg = G.bs.process_msg(full_msg)
            G.bs.msg_add(bmsg)
            G.bmsgs.append(bmsg)
            tkns = list(bmsg)
            N = len(tkns) - 1
            t0 = tkns[0]
            tN = tkns[N]
            k0 = ( bmsg.ptn_id(), 0, t0.tkn_id() )
            kN = ( bmsg.ptn_id(), N, tN.tkn_id() )
            v0 = G.ptn_tkns.setdefault(k0, list(k0) + [0])
            vN = G.ptn_tkns.setdefault(kN, list(kN) + [0])
            v0[-1] += 1
            vN[-1] += 1
        # insert w/o error is enough

    def test_005_msg_verify(self):
        G.mitr = Bq.Bmsg_iter(G.bs)
        G.msgs_5 = [ m for m in G.mitr ]
        db_msgs = [ str(m).replace('.000000', '') for m in G.msgs_5 ]
        gen_msgs = [ m[-1] for m in messages() ]
        # check if we get all messages
        self.assertTrue(set(db_msgs) == set(gen_msgs))
        # check if the messages are ordered by time-comp
        tc = [ m[:35] for m in db_msgs ]
        _tc = list(tc)
        _tc.sort()
        self.assertTrue(tc == _tc)

    def test_006_ptn_verify(self):
        G.pitr = Bq.Bptn_iter(G.bs)
        G.ptns = [ p for p in G.pitr ]
        db_ptns = [ str(p) for p in G.ptns ]
        self.assertTrue( set(db_ptns) == set(B_PATTERNS) )

    def test_007_tkn_hist_update_3600(self):
        G.tkn_hist_3600 = dict()
        for ts, host, msg, full_msg in messages():
            tkn = G.bs.tkn_by_name(host)
            k = ( (ts//3600)*3600, 3600, tkn.tkn_id())
            G.bs.tkn_hist_update(*k)
            h = G.tkn_hist_3600.setdefault(k, [k[1], k[0], k[2], 0 ])
            h[-1] += 1

    def test_008_tkn_hist_update_3600_verify(self):
        G.tkn_hist_iter = Bq.Btkn_hist_iter(G.bs)
        db_data = [ tuple(h) for h in G.tkn_hist_iter ]
        test_data = [ tuple(h) for h in G.tkn_hist_3600.values() ]
        db_data.sort()
        test_data.sort()
        self.assertTrue( db_data == test_data )

    def test_009_ptn_hist_update_3600(self):
        G.ptn_hist_3600 = dict()
        G.comp_hist_3600 = dict()
        for m in G.msgs_5:
            ptn_id = m.ptn_id()
            comp_id = m.comp_id()
            bw = 3600
            sec = (m.tv_sec() // bw) * bw
            # udpate in db
            G.bs.ptn_hist_update(ptn_id, comp_id, sec, bw)
            # update hist for verification
            k_ptn  = (bw, sec, ptn_id)
            k_comp = (bw, sec, comp_id, ptn_id)
            ptn_hist = G.ptn_hist_3600.setdefault(k_ptn, list(k_ptn) + [0])
            comp_hist = G.comp_hist_3600.setdefault(k_comp, list(k_comp) + [0])
            ptn_hist[-1]  += 1
            comp_hist[-1] += 1

    def test_010_ptn_hist_update_3600_verify_ptn(self):
        G.ptn_hist_iter = Bq.Bptn_hist_iter(G.bs)
        db_data = [ tuple(h) for h in G.ptn_hist_iter ]
        test_data = [ tuple(h) for h in G.ptn_hist_3600.values() ]
        db_data.sort()
        test_data.sort()
        self.assertTrue( db_data == test_data )

    def test_011_ptn_hist_update_3600_verify_comp(self):
        G.comp_hist_iter = Bq.Bcomp_hist_iter(G.bs)
        db_data = [ tuple(h) for h in G.comp_hist_iter ]
        test_data = [ tuple(h) for h in G.comp_hist_3600.values() ]
        db_data.sort()
        test_data.sort()
        self.assertTrue( db_data == test_data )

    def test_012_msg_filter(self):
        G.mitr = Bq.Bmsg_iter(G.bs)
        comp = G.bs.tkn_by_name('node00001')
        comp_id = comp.tkn_id()
        G.mitr.set_filter(comp_id = comp_id)
        G.bmsgs_012 = [ m for m in G.mitr ]
        cmp_msgs = [ full_msg for ts, host, msg, full_msg in messages() \
                               if host == 'node00001' ]
        db_msgs  = [ str(m).replace('.000000', '') for m in G.bmsgs_012 ]
        self.assertTrue(set(cmp_msgs) == set(db_msgs))

    def test_013_tkn_hist_filter(self):
        G.hitr = Bq.Btkn_hist_iter(G.bs)
        comp = G.bs.tkn_by_name('node00001')
        comp_id = comp.tkn_id()
        G.hitr.set_filter(tkn_id = comp_id)
        G.hists_013 = [ h for h in G.hitr ]
        db_data = [ tuple(h) for h in G.hists_013 ]
        cmp_data = [ tuple(h) for h in G.tkn_hist_3600.values() \
                       if h[2] == comp_id ]
        self.assertTrue(set(cmp_data) == set(db_data))

    def test_014_ptn_hist_filter(self):
        G.hitr = Bq.Bptn_hist_iter(G.bs)
        ptn_id = 258
        G.hitr.set_filter(ptn_id = ptn_id)
        G.hists_014 = [ h for h in G.hitr ]
        db_data = [ tuple(h) for h in G.hists_014 ]
        cmp_data = [ tuple(h) for h in G.ptn_hist_3600.values() \
                       if h[2] == ptn_id ]
        self.assertTrue(set(cmp_data) == set(db_data))

    def test_015_comp_hist_filter(self):
        G.hitr = Bq.Bcomp_hist_iter(G.bs)
        ptn_id = 258
        G.hitr.set_filter(ptn_id = ptn_id)
        G.hists_015 = [ h for h in G.hitr ]
        db_data = [ tuple(h) for h in G.hists_015 ]
        cmp_data = [ tuple(h) for h in G.comp_hist_3600.values() \
                       if h[3] == ptn_id ]
        self.assertTrue(set(cmp_data) == set(db_data))

    def test_016_ptn_tkn_filter_verify(self):
        ptn_id = 258
        tkn_pos = 0
        G.bptn_tkn_iter = Bq.Bptn_tkn_iter(G.bs)
        G.bptn_tkn_iter.set_filter(ptn_id = ptn_id, tkn_pos = tkn_pos)
        G.bptn_tkns = [ h for h in G.bptn_tkn_iter ]
        db_data = [ (ptn_id, tkn_pos, h.tkn_id(), h.tkn_count() ) for h in G.bptn_tkns ]
        cmp_data = [ tuple(h) for h in G.ptn_tkns.values() \
                              if h[0]== ptn_id and h[1] == tkn_pos ]
        self.assertTrue(set(cmp_data) == set(db_data))

    def test_017_ptn_attr_new(self):
        G.bs.attr_new("TAG")
        G.bs.attr_new("IS_BAD")

    def test_018_ptn_attr_find(self):
        v0 = G.bs.attr_find("TAG")
        v1 = G.bs.attr_find("IS_BAD")
        v2 = G.bs.attr_find("LALALA")
        self.assertTrue(v0)
        self.assertTrue(v1)
        self.assertFalse(v2)

    def test_019_ptn_attr_value_add_set(self):
        G.pi = Bq.Bptn_iter(G.bs)
        for ptn in G.pi:
            ptn_id = ptn.ptn_id()
            if ptn_id % 2 == 0:
                G.bs.ptn_attr_value_add(ptn_id, "TAG", "even")
                G.bs.ptn_attr_value_add(ptn_id, "TAG", "EVEN")
            else:
                G.bs.ptn_attr_value_add(ptn_id, "TAG", "odd")
                G.bs.ptn_attr_value_add(ptn_id, "TAG", "ODD")
            if ptn_id == 256:
                G.bs.ptn_attr_value_set(ptn_id, "IS_BAD", "1")
            else:
                G.bs.ptn_attr_value_set(ptn_id, "IS_BAD", "0")

    def test_020_ptn_attr_value_verify(self):
        G.pi = Bq.Bptn_iter(G.bs)
        cmp_odd = set()
        cmp_even = set()
        for ptn in G.pi:
            ptn_id = ptn.ptn_id()
            cmp_avs = set()
            v = G.bs.ptn_attr_get(ptn_id, "IS_BAD")
            if ptn_id == 256:
                self.assertTrue( v == "1" )
                cmp_avs.add(("IS_BAD", "1"))
            else:
                self.assertTrue( v == "0" )
                cmp_avs.add(("IS_BAD", "0"))
            db_avs = set(ptn.attr_values())
            if ptn_id % 2 == 0:
                cmp_even.add(ptn_id)
                cmp_avs.update([ ("TAG", "EVEN"), ("TAG", "even") ])
            else:
                cmp_odd.add(ptn_id)
                cmp_avs.update([ ("TAG", "ODD"), ("TAG", "odd") ])
            self.assertTrue( db_avs == cmp_avs )

    def test_021_ptn_by_attr_verify(self):
        cmp_odd = set()
        cmp_even = set()
        G.pi = Bq.Bptn_iter(G.bs)
        for ptn in G.pi:
            ptn_id = ptn.ptn_id()
            if ptn_id % 2 == 0:
                cmp_even.add(ptn_id)
            else:
                cmp_odd.add(ptn_id)
        G.i = Bq.Bptn_attr_iter(G.bs)
        G.i.set_filter(attr_type = "TAG", attr_value = "even")
        db_even_objs = [ o for o in G.i ]
        db_even = set( o.ptn_id() for o in db_even_objs )
        G.i = Bq.Bptn_attr_iter(G.bs)
        G.i.set_filter(attr_type = "TAG", attr_value = "odd")
        db_odd_objs = [ o for o in G.i ]
        db_odd = set( o.ptn_id() for o in db_odd_objs )
        self.assertTrue( len(db_even_objs) == len(cmp_even) )
        self.assertTrue( len(db_odd_objs)  == len(cmp_odd) )


if __name__ == "__main__":
    LOGFMT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
    DATEFMT = "%F %T"
    logging.basicConfig(format=LOGFMT, datefmt=DATEFMT)
    log.setLevel(logging.INFO)
    MAKE_STORE = True
    unittest.main(verbosity=2, failfast=1)
