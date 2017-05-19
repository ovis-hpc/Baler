#!/usr/bin/env python

import itertools
import logging
import unittest
import os
import shutil
from StringIO import StringIO
from test_util.util import *

logger = logging.getLogger(__name__)

class Debug(object): pass

DEBUG = Debug() # DEBUG object

BTEST_N_DAEMONS = 4

FWD = 1
REV = 2

def print_head(lst, n = 10):
    i = 0
    for obj in lst:
        print obj
        i += 1
        if i == n:
            break


class TestBSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        shutil.rmtree("store.agg", ignore_errors=True)
        cls.bsa = BStore.open("bstore_agg", "bstore_agg.cfg",
                                        os.O_RDWR|os.O_CREAT, 0755)
        bss = [];
        for i in range(0, 4):
            _b = BStore.open("bstore_sos", "store.%d" % i, os.O_RDWR, 0)
            bss.append(_b)
        cls.bss = bss
        DEBUG.bss = bss
        DEBUG.bsa = cls.bsa
        pass

    @classmethod
    def tearDownClass(cls):
        del cls.bss
        del cls.bsa
        pass

    def tkn_stats_verify(self, tkn0):
        bss = self.bss
        tkn = None
        for bs in bss:
            _tkn = bs.tknFindByName(tkn0.tkn_text)
            if not tkn:
                tkn = _tkn
            else:
                tkn += _tkn
            self.assertEqual(_tkn.tkn_text, tkn0.tkn_text)
        self.assertEqual(tkn.tkn_count, tkn0.tkn_count)
        self.assertEqual(tkn.tkn_type_mask, tkn0.tkn_type_mask)

    def test_tkn(self):
        texts = ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven"]
        for text in texts:
            tkn0 = self.bsa.tknFindByName(text)
            tkn1 = self.bsa.tknFindById(tkn0.tkn_id)
            # tkn obtained by id and name should be the same.
            self.assertEqual(tkn0.tkn_id, tkn1.tkn_id)
            self.assertEqual(tkn0.tkn_text, tkn1.tkn_text)
            self.assertEqual(tkn0.tkn_count, tkn1.tkn_count)
            self.assertEqual(tkn0.tkn_type_mask, tkn1.tkn_type_mask)
            # check the aggregate statistics
            self.tkn_stats_verify(tkn0)

    def test_tkn_iter(self):
        bs_tkn = {}

        for bs in self.bss:
            for tkn in TknIter(bs):
                _t = None
                try:
                    bs_tkn[tkn.tkn_text] += tkn
                except KeyError:
                    bs_tkn[tkn.tkn_text] = tkn

        count = 0
        for tkn in TknIter(self.bsa):
            _t = bs_tkn[tkn.tkn_text]
            count += 1
            self.assertEqual(tkn.tkn_text, _t.tkn_text)
            self.assertEqual(tkn.tkn_count, _t.tkn_count)
            self.assertEqual(tkn.tkn_type_mask, _t.tkn_type_mask)
        self.assertEqual(len(bs_tkn), count)
        return

    def __test_iter_fwd_rev(self, ItrCls, N, *args, **kwargs):
        itr = ItrCls(self.bsa, *args, **kwargs)
        stack = [itr.first()]
        for i in range(0, N):
            stack.append(itr.next())
        tkn = itr.obj()
        while tkn:
            self.assertEqual(tkn, stack.pop())
            tkn = itr.prev()
        self.assertEqual(len(stack), 0)

    def __test_iter_rev_fwd(self, ItrCls, N, *args, **kwargs):
        itr = ItrCls(self.bsa, *args, **kwargs)
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

    def test_tkn_iter_pos(self):
        itr0 = TknIter(self.bsa)
        itr1 = TknIter(self.bsa)

        tkn0 = itr0.first()
        tkn0 = itr0.next()
        tkn0 = itr0.next()

        pos = itr0.get_pos()
        self.assertIsNotNone(pos)
        itr1.set_pos(pos)

        tkn1 = itr1.obj()

        self.assertEqual(tkn0, tkn1)

        count = 10

        while count:
            tkn0 = itr0.next()
            tkn1 = itr1.next()
            self.assertEqual(tkn0, tkn1)
            count -= 1
        self.assertEqual(count, 0)
        return

    def test_ptn(self):
        ptn_table = {}
        for bs in self.bss:
            for ptn in PtnIter(bs):
                _ptn = None
                try:
                    _ptn = ptn_table[str(ptn)]
                except KeyError:
                    _ptn = ptn
                    ptn_table[str(ptn)] = ptn
                else:
                    _ptn += ptn
        count = 0
        for ptn in PtnIter(self.bsa):
            _ptn = ptn_table[str(ptn)]
            self.assertEqual(_ptn.count, ptn.count)
            self.assertEqual(_ptn.first_seen, ptn.first_seen)
            self.assertEqual(_ptn.last_seen, ptn.last_seen)
            count += 1
        self.assertTrue(count)

    def test_ptn_pos_obj(self):
        itr1 = PtnIter(self.bsa)
        p1 = itr1.first()
        self.assertTrue(p1)
        p1 = itr1.next()
        self.assertTrue(p1)

        pos = itr1.get_pos()
        assert(pos)

        itr2 = PtnIter(self.bsa)
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

    def test_ptn_iter_fwd(self):
        pass

    def debug_ptn_iter_fwd_rev(self):
        itr1 = PtnIter(self.bsa)
        itr2 = PtnIter(self.bsa)
        print""
        print "---- rev ----"
        ptn = itr2.last()
        while ptn:
            print str(ptn)
            ptn = itr2.prev()
        print "---- fwd ----"
        for ptn in itr1:
            print str(ptn)

    def test_ptn_iter_fwd_rev(self):
        itr1 = PtnIter(self.bsa)
        itr2 = PtnIter(self.bsa)
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

    def test_ptn_iter_card(self):
        itr = PtnIter(self.bsa)
        card = itr.card()
        count = 0
        for ptn in itr:
            count += 1
        self.assertEqual(count, card)

    def test_ptn_iter_find_id_fwd(self):
        itr = PtnIter(self.bsa)
        ptn = itr.find_fwd(ptn_id=1)
        while ptn:
            next_ptn = itr.next()
            if not next_ptn:
                break
            self.assertGreaterEqual(next_ptn.ptn_id , ptn.ptn_id)
            ptn = next_ptn

    def test_ptn_iter_find_id_pos(self):
        itr1 = PtnIter(self.bsa)
        ptn1 = itr1.find_fwd(ptn_id=1)
        ptn1 = itr1.next()
        ptn1 = itr1.next()
        pos = itr1.get_pos()
        self.assertIsNotNone(pos)
        itr2 = PtnIter(self.bsa)
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

    def test_msg_iter_card(self):
        sum_card = 0
        itr0 = MsgIter(self.bsa)
        card = itr0.card()
        for bs in self.bss:
            itr = MsgIter(bs)
            sum_card += itr.card()
        self.assertEqual(card, sum_card)

    def test_msg_iter_fwd(self):
        itr = MsgIter(self.bsa)
        msgs1 = []
        for msg in itr:
            host_str = str(msg.host)
            host_check = msg.text().split(" ")[0]
            self.assertEqual(host_str, host_check)
            msgs1.append(str(msg))
        msgs1.sort()
        msgs2 = []
        for bs in self.bss:
            for msg in MsgIter(bs):
                msgs2.append(str(msg))
        msgs2.sort()
        self.assertEqual(msgs1, msgs2)

    def debug_msg_iter_rev(self):
        DEBUG.msgs = msgs = []
        DEBUG.smsgs = smsgs = []
        for bs in self.bss:
            itr = MsgIter(bs)
            msg = itr.last()
            msgs.append(msg)
            smsgs.append(str(msg))
        itr = MsgIter(self.bsa)
        DEBUG.msg = msg = itr.last()
        self.assertIn(str(msg), smsgs)
        return
        for bs in self.bss:
            DEBUG.old_msg = old_msg = None
            DEBUG.count = 0
            for msg in MsgRevIter(bs):
                DEBUG.msg = msg
                if old_msg:
                    self.assertLessEqual(msg.timestamp, old_msg.timestamp)
                    if (msg.timestamp == old_msg.timestamp):
                        self.assertLessEqual(msg.comp_id, old_msg.comp_id)
                DEBUG.old_msg = old_msg = msg
                DEBUG.count += 1
        old_msg = None
        for msg in MsgRevIter(self.bsa):
            if old_msg:
                self.assertLessEqual(msg.timestamp, old_msg.timestamp)
                if (msg.timestamp == old_msg.timestamp):
                    self.assertLessEqual(msg.comp_id, old_msg.comp_id)
            old_msg = msg

    def test_msg_iter_rev(self):
        DEBUG.msgs1 = msgs1 = [m for m in MsgRevIter(self.bsa)]
        DEBUG.msgs2 = msgs2 = [m for m in MsgIter(self.bsa)]
        DEBUG.smsgs1 = smsgs1 = [str(m) for m in msgs1]
        DEBUG.smsgs2 = smsgs2 = [str(m) for m in msgs2]
        DEBUG.d1 = d1 = set(smsgs1) - set(smsgs2)
        DEBUG.d2 = d2 = set(smsgs2) - set(smsgs1)
        self.assertEqual(d1, set())
        self.assertEqual(d2, set())
        smsgs2.reverse()
        self.assertEqual(smsgs1, smsgs2)
        return

    def test_msg_iter_fwd_rev(self):
        itr = MsgIter(self.bsa)
        msgs1 = []
        msgs2 = []
        count = 20
        msg = itr.first()
        while msg and count:
            msgs1.append(msg)
            count -= 1
            msg = itr.next()
        msg = itr.prev()
        while msg:
            msgs2.append(msg)
            msg = itr.prev()
        msgs2.reverse()
        self.assertTrue(len(msgs1))
        self.assertEqual(msgs1, msgs2)

    def test_msg_iter_filter_comp(self):
        name = "node00044"
        comp = self.bsa.tknFindByName(name)
        self.assertIsNotNone(comp)
        msgs0 = []
        msgs1 = []
        for msg in MsgIterFilter(self.bsa, comp_id=comp.tkn_id):
            self.assertEqual(msg.comp_id, comp.tkn_id)
            msgs0.append(str(msg))
        for bs in self.bss:
            comp = bs.tknFindByName(name)
            if not comp:
                continue
            for msg in MsgIterFilter(bs, comp_id=comp.tkn_id):
                self.assertEqual(msg.comp_id, comp.tkn_id)
                msgs1.append(str(msg))
        msgs0.sort()
        msgs1.sort()
        self.assertTrue(len(msgs0)>0)
        self.assertEqual(msgs0, msgs1)

    def test_msg_iter_filter_comp_time(self):
        name = "node00044"
        bsa_time = 1435363200
        bsa_tv = (bsa_time, 0)
        comp = self.bsa.tknFindByName(name)
        self.assertIsNotNone(comp)
        msgs0 = []
        msgs1 = []
        for msg in MsgIterFilter(self.bsa, tv_begin=bsa_tv, comp_id=comp.tkn_id):
            self.assertGreaterEqual(msg.timestamp, bsa_time)
            self.assertEqual(msg.comp_id, comp.tkn_id)
            msgs0.append(str(msg))
        for bs in self.bss:
            comp = bs.tknFindByName(name)
            if not comp:
                continue
            for msg in MsgIterFilter(bs, tv_begin=bsa_tv, comp_id=comp.tkn_id):
                self.assertGreaterEqual(msg.timestamp, bsa_time)
                self.assertEqual(msg.comp_id, comp.tkn_id)
                msgs1.append(str(msg))
        msgs0.sort()
        msgs1.sort()
        self.assertTrue(len(msgs0)>0)
        self.assertEqual(msgs0, msgs1)

    def test_msg_iter_filter_time(self):
        bsa_time = 1435363200
        bsa_tv = (bsa_time, 0)
        msgs0 = []
        msgs1 = []
        for msg in MsgIterFilter(self.bsa, tv_begin=bsa_tv):
            self.assertGreaterEqual(msg.timestamp, bsa_time)
            msgs0.append(str(msg))
        for bs in self.bss:
            for msg in MsgIterFilter(bs, tv_begin=bsa_tv):
                self.assertGreaterEqual(msg.timestamp, bsa_time)
                msgs1.append(str(msg))
        msgs0.sort()
        msgs1.sort()
        self.assertTrue(len(msgs0)>0)
        self.assertEqual(msgs0, msgs1)

    def test_msg_iter_filter_ptn(self):
        bsa_ptn_id = 263
        msgs0 = []
        msgs1 = []
        for msg in MsgIterFilter(self.bsa, ptn_id=bsa_ptn_id):
            self.assertEqual(msg.ptn_id, bsa_ptn_id)
            msgs0.append(str(msg))
        ptn = self.bsa.ptnFindById(bsa_ptn_id)
        for bs in self.bss:
            _ptn = bs.ptnFindByStr(str(ptn))
            if not _ptn:
                continue
            for msg in MsgIterFilter(bs, ptn_id=_ptn.ptn_id):
                self.assertEqual(msg.ptn_id, _ptn.ptn_id)
                msgs1.append(str(msg))
        msgs0.sort()
        msgs1.sort()
        self.assertTrue(len(msgs0)>0)
        self.assertEqual(msgs0, msgs1)

    def test_msg_iter_filter_ptn_time(self):
        bsa_ptn_id = 263
        bsa_time = 1435363200
        bsa_tv = (bsa_time, 0)
        msgs0 = []
        msgs1 = []

        for msg in MsgIterFilter(self.bsa, ptn_id=bsa_ptn_id, tv_begin=bsa_tv):
            self.assertEqual(msg.ptn_id, bsa_ptn_id)
            self.assertGreaterEqual(msg.timestamp, bsa_time)
            msgs0.append(str(msg))

        ptn = self.bsa.ptnFindById(bsa_ptn_id)
        for bs in self.bss:
            _ptn = bs.ptnFindByStr(str(ptn))
            if not _ptn:
                continue
            for msg in MsgIterFilter(bs, ptn_id=_ptn.ptn_id, tv_begin=bsa_tv):
                self.assertEqual(msg.ptn_id, _ptn.ptn_id)
                self.assertGreaterEqual(msg.timestamp, bsa_time)
                msgs1.append(str(msg))
        msgs0.sort()
        msgs1.sort()
        self.assertTrue(len(msgs0)>0)
        self.assertEqual(msgs0, msgs1)

    def test_msg_iter_filter_ptn_comp_time(self):
        bsa_ptn_id = 263
        name = "node00063"
        bsa_time = 1435363200
        bsa_tv = (bsa_time, 0)
        msgs0 = []
        msgs1 = []
        comp = self.bsa.tknFindByName(name)

        for msg in MsgIterFilter(self.bsa, ptn_id=bsa_ptn_id, tv_begin=bsa_tv,
                                 comp_id=comp.tkn_id):
            self.assertEqual(msg.ptn_id, bsa_ptn_id)
            self.assertEqual(msg.comp_id, comp.tkn_id)
            self.assertGreaterEqual(msg.timestamp, bsa_time)
            msgs0.append(str(msg))

        ptn = self.bsa.ptnFindById(bsa_ptn_id)
        for bs in self.bss:
            _ptn = bs.ptnFindByStr(str(ptn))
            if not _ptn:
                continue
            _comp = bs.tknFindByName(name)
            if not _comp:
                continue
            for msg in MsgIterFilter(bs, ptn_id=_ptn.ptn_id, tv_begin=bsa_tv,
                                     comp_id=_comp.tkn_id):
                self.assertEqual(msg.ptn_id, _ptn.ptn_id)
                self.assertEqual(msg.comp_id, _comp.tkn_id)
                self.assertGreaterEqual(msg.timestamp, bsa_time)
                msgs1.append(str(msg))
        msgs0.sort()
        msgs1.sort()
        self.assertTrue(len(msgs0)>0)
        self.assertEqual(msgs0, msgs1)

    def test_msg_iter_pos(self):
        n = 10
        limit = 20

        itr0 = MsgIter(self.bsa)
        msg0 = itr0.first()
        n -= 1
        while n:
            msg0 = itr0.next()
            n -= 1

        pos = itr0.get_pos()

        itr1 = MsgIter(self.bsa)
        itr1.set_pos(pos)
        msg1 = itr1.obj()
        self.assertEqual(msg0, msg1)

        while limit:
            msg0 = itr0.next()
            msg1 = itr1.next()
            self.assertEqual(msg0, msg1)
            limit -= 1

    def _ptn_tkn_table(self, bs):
        table = {}
        for ptn in PtnIter(bs):
            for i in range(0, len(ptn.tkn_list)):
                for tkn in PtnTknIter(bs, ptn.ptn_id, i):
                    key = (str(ptn), i, str(tkn))
                    table[key] = tkn.tkn_count
        return table

    def _ptn_tkn_table_merge(self, tb0, tb1 = {}):
        # merge contents of tb1 into tb0
        for (k,v) in tb1.iteritems():
            try:
                tb0[k] += v
            except KeyError:
                tb0[k] = v
        return tb0

    def test_ptn_tkn_iter(self):
        s0 = self._ptn_tkn_table(self.bsa)
        s1 = {}
        for bs in self.bss:
            self._ptn_tkn_table_merge(s1, self._ptn_tkn_table(bs))
        self.assertGreater(len(s0), 0)
        self.assertEqual(s0, s1)

    def test_ptn_tkn_iter_obj(self):
        itr = PtnTknIter(self.bsa, 257, 0)
        tkn0 = itr.first()
        tkn0 = itr.next()
        tkn0 = itr.next()
        tkn1 = itr.obj()
        self.assertEqual(tkn0, tkn1)

    def test_ptn_tkn_iter_pos(self):
        bs = self.bsa
        itr0 = PtnTknIter(bs, 256, 0)
        tkn0 = itr0.first()
        tkn0 = itr0.next()
        tkn0 = itr0.next()

        pos = itr0.get_pos()
        itr1 = PtnTknIter(bs, 0, 0)
        itr1.set_pos(pos)
        tkn1 = itr1.obj()

        self.assertEqual(tkn0, tkn1)

        while tkn0 and tkn1:
            tkn0 = itr0.next()
            tkn1 = itr1.next()
            self.assertEqual(tkn0, tkn1)

    def __tkn_hist_data(self, bs = BStore(None, None), name = "Zero"):
        data = {}
        tkn = bs.tknFindByName(name)
        if not tkn:
            return data
        itr = TknHistIter(bs, tkn_id=tkn.tkn_id, bin_width=3600)
        for hist in itr:
            self.assertEqual(tkn.tkn_id, hist.tkn_id)
            key = (hist.bin_width, hist.time)
            self.assertFalse(key in data)
            data[key] = hist.tkn_count
        return data

    def __hist_data_merge(self, d0, d = {}):
        if not d:
            return d0
        for (k,v) in d.iteritems():
            try:
                d0[k] += v
            except KeyError:
                d0[k] = v
        return d0

    def __test_tkn_hist_fwd_iter(self, name):
        bssd = {}
        for bs in self.bss:
            d = self.__tkn_hist_data(bs, name)
            self.__hist_data_merge(bssd, d)
        bsad = self.__tkn_hist_data(self.bsa, name)
        self.assertGreater(len(bsad), 0)
        self.assertEqual(bsad, bssd)

    def test_tkn_hist_fwd_iter(self):
        self.__test_tkn_hist_fwd_iter("Zero")
        self.__test_tkn_hist_fwd_iter("node00012")

    def test_tkn_hist_obj(self):
        bs = self.bss[0]
        name = "Zero"
        tkn = bs.tknFindByName(name)
        itr = TknHistIter(bs, tkn_id=tkn.tkn_id, bin_width=3600)
        count = 0
        for x in itr:
            o = itr.obj()
            self.assertEqual(x, o)
            count += 1
        self.assertGreater(count, 0)

    def __test_hist_iter_pos(self, ItrCls, bin_width, time, _id):
        # _id can be tkn_id, ptn_id or (comp_id, ptn_id)
        if ItrCls == CompHistIter:
            itr1 = ItrCls(self.bsa,
                          bin_width=bin_width,
                          tv_begin=(time, 0),
                          comp_id=_id[0],
                          ptn_id=_id[1])
            itr2 = ItrCls(self.bsa)
        else:
            itr1 = ItrCls(self.bsa,
                          tkn_id=_id,
                          ptn_id=_id,
                          bin_width=bin_width,
                          tv_begin=(time, 0))
            itr2 = ItrCls(self.bsa)
        itr1.first()
        itr1.next()
        itr1.next()
        itr1.next()
        itr1.next()
        pos = itr1.get_pos()
        self.assertIsNotNone(pos)
        itr2.set_pos(pos)

        obj1 = itr1.obj()
        obj2 = itr2.obj()
        self.assertIsNotNone(obj1)
        while obj1 and obj2:
            self.assertEqual(obj1, obj2)
            obj1 = itr1.next()
            obj2 = itr2.next()
        self.assertEqual(obj1, obj2)

    def test_tkn_hist_iter_filter(self):
        BW = [60, 3600]
        TS = [0, BTEST_TS_BEGIN + 4*BTEST_TS_INC]
        TKN = [None, "Zero"]

        for (bw, ts, tkn) in itertools.product(BW, TS, TKN):
            tkn_id = 0 if not tkn else self.bsa.tknFindByName(tkn).tkn_id
            itr = TknHistIter(self.bsa, bin_width=bw, tv_begin=(ts, 0),
                              tkn_id=tkn_id)
            for h in itr:
                if tkn_id:
                    self.assertEqual(tkn_id, h.tkn_id)
                self.assertEqual(bw, h.bin_width)
                self.assertLessEqual(ts, h.time)

    def test_tkn_hist_iter_pos(self):
        BW = [60, 3600]
        TS = [0, BTEST_TS_BEGIN + 4*BTEST_TS_INC]
        TKN = [None, "Zero"]
        if False:
            print ""
        for (bw, ts, tkn) in itertools.product(BW, TS, TKN):
            tkn_id = 0 if not tkn else self.bsa.tknFindByName(tkn).tkn_id
            if False:
                # debug stuff
                print "(%d, %d, '%s', %d)" % (bw, ts, tkn, tkn_id)
            self.__test_hist_iter_pos(TknHistIter, bw, ts, tkn_id)

    def test_ptn_hist_iter_pos(self):
        BW = [60, 3600]
        TS = [0, BTEST_TS_BEGIN + 4*BTEST_TS_INC]
        PTN = [263]
        for (bw, ts, ptn_id) in itertools.product(BW, TS, PTN):
            self.__test_hist_iter_pos(PtnHistIter, bw, ts, ptn_id)

    def __ptn_hist_data(self, bs):
        data = {}
        for ptn in PtnIter(bs):
            pdata = {}
            for hist in PtnHistIter(bs, ptn_id=ptn.ptn_id, bin_width=3600):
                key = (hist.bin_width, hist.time)
                self.assertFalse(key in pdata)
                pdata[key] = hist.msg_count
            self.assertTrue(pdata)
            key = str(ptn)
            self.assertFalse(key in data)
            data[key] = pdata
        self.assertTrue(data)
        return data

    def __ptn_hist_data_merge(self, d0, d1={}):
        # merge d1 data into d0
        for (k1, m1) in d1.iteritems():
            try:
                m0 = d0[k1]
            except KeyError:
                m0 = {}
                d0[k1] = m0
            for (k, v) in m1.iteritems():
                try:
                    m0[k] += v
                except KeyError:
                    m0[k] = v
        return d0

    def __ptn_hist_data_print(self, data = {}):
        print "------ BEGIN ------"
        for (k, v) in data.iteritems():
            print "key:", k
            for (_k, _v) in v.iteritems():
                print "  ", _k, _v
        print "------ END ------"

    def test_ptn_hist_fwd_iter(self):
        data_bsa = self.__ptn_hist_data(self.bsa)
        data_bss = {}
        for bs in self.bss:
            tmp = self.__ptn_hist_data(bs)
            self.__ptn_hist_data_merge(data_bss, tmp)
        #self.__ptn_hist_data_print(data_bsa)
        #self.__ptn_hist_data_print(data_bss)
        self.assertEqual(data_bsa, data_bss)

    def test_ptn_hist_obj(self):
        itr = PtnHistIter(self.bsa, ptn_id=256, bin_width=3600)
        h0 = itr.first()
        h0 = itr.next()
        h0 = itr.next()
        h1 = itr.obj()
        self.assertEqual(h0, h1)

    def __comp_hist_data(self, bs, bin_width, time, comp_id, ptn_id):
        ret = {}
        prev = None
        kwargs = {
            "bin_width": bin_width,
            "tv_begin": (time, 0),
            "comp_id": comp_id,
            "ptn_id": ptn_id
        }
        for hist in CompHistIter(bs, **kwargs):
            if prev:
                self.assertGreater(hist, prev)
            comp = bs.tknFindById(hist.comp_id)
            ptn = bs.ptnFindById(hist.ptn_id)
            k = (bin_width, hist.time, str(comp), str(ptn))
            self.assertNotIn(k, ret)
            ret[k] = hist.msg_count
            prev = hist
        return ret

    def __comp_hist_data_merge(self, a, b):
        # merge b into a
        for (k, v) in b.iteritems():
            try:
                a[k] += v
            except KeyError:
                a[k] = v
        return a

    def __test_comp_hist_fwd_iter(self, bin_width, time, cname, pstr):
        comp_id = self.bsa.getTknId(cname)
        ptn_id = self.bsa.getPtnId(pstr)
        bsa_hist = self.__comp_hist_data(self.bsa, bin_width, time,
                                         comp_id, ptn_id)
        self.assertGreater(len(bsa_hist), 0)
        bss_hist = {}
        for bs in self.bss:
            comp_id = bs.getTknId(cname)
            ptn_id = bs.getPtnId(pstr)

            if cname and not comp_id:
                continue
            if pstr and not ptn_id:
                continue
            tmp = self.__comp_hist_data(bs, bin_width, time, comp_id, ptn_id)
            self.__comp_hist_data_merge(bss_hist, tmp)
        self.assertEqual(bsa_hist, bss_hist)
        self.assertGreater(len(bsa_hist), 0)

    def test_comp_hist_fwd_iter(self):
        # no filter
        self.__test_comp_hist_fwd_iter(3600, 0, None, None)
        # filter by comp
        self.__test_comp_hist_fwd_iter(3600, 0, "node00012", None)
        self.__test_comp_hist_fwd_iter(3600, 0, "node00000", None)

        # filter by pattern
        ptn = self.bsa.ptnFindById(256)
        self.__test_comp_hist_fwd_iter(3600, 0, None, str(ptn))

        # filter by both
        self.__test_comp_hist_fwd_iter(3600, 0, "node00000", str(ptn))


if __name__ == "__main__":
    LOGFMT = '%(asctime)s %(name)s %(levelname)s: %(message)s'
    logging.basicConfig(format=LOGFMT)
    logger.setLevel(logging.INFO)
    _pystart = os.environ.get("PYTHONSTARTUP")
    if _pystart:
        execfile(_pystart)
    unittest.TestLoader.testMethodPrefix = "test_"
    unittest.main()
