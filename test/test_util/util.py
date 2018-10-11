#!/usr/bin/env python

import itertools
import logging
import unittest
import time
import os
import re
import subprocess
from StringIO import StringIO
from baler import Bq

logger = logging.getLogger(__name__)

def TYPE_MASK(_type):
    return 1<<(_type-1)


def get_btest_var_table():
    rex = re.compile("([^ ]+) (.*)")
    cmd = "source config.sh >/dev/null 2>&1; for X in BSTORE ${!BTEST_*}; do echo $X ${!X}; done"
    out = subprocess.check_output(cmd, shell=True, executable="/bin/bash")
    sio = StringIO(out)
    table = {}
    for line in sio:
        line = line.rstrip()
        m = rex.match(line)
        if not m:
            continue
        g = m.groups()
        table[g[0]] = g[1]
    return table


BTEST_VARS = get_btest_var_table()


def get_btest_int(var):
    try:
        return int(BTEST_VARS[var])
    except:
        return 0


def get_btest_var_map(var, _map, default):
    val = None
    try:
        val = BTEST_VARS[var]
    except KeyError:
        return default
    else:
        # good
        return _map(val)


BTEST_BIN_RSYSLOG_PORT = get_btest_int("BTEST_BIN_RSYSLOG_PORT")
BTEST_TS_BEGIN = get_btest_int("BTEST_TS_BEGIN")
BTEST_TS_INC = get_btest_int("BTEST_TS_INC")
BTEST_TS_LEN = get_btest_int("BTEST_TS_LEN")
BTEST_NODE_BEGIN = get_btest_int("BTEST_NODE_BEGIN")
BTEST_NODE_LEN = get_btest_int("BTEST_NODE_LEN")
BTEST_N_PATTERNS = get_btest_int("BTEST_N_PATTERNS")

BTEST_BLOCKING_MQ = get_btest_int("BTEST_BLOCKING_MQ")
BTEST_MQ_THREADS = get_btest_int("BTEST_MQ_THREADS")
BTEST_MQ_DEPTH = get_btest_int("BTEST_MQ_DEPTH")
BTEST_TKN_HIST = get_btest_int("BTEST_TKN_HIST")
BTEST_PTN_HIST = get_btest_int("BTEST_PTN_HIST")
BTEST_PTN_TKN = get_btest_int("BTEST_PTN_TKN")

try:
    BTEST_INPUT_DIR = BTEST_VARS["BTEST_INPUT_DIR"]
except:
    BTEST_INPUT_DIR = None

BTEST_TKN_TYPE_MASK = get_btest_var_map("BTEST_TKN_TYPE_MASK",
                                        Bq.btkn_type_mask_from_str, 0)

BTEST_N_DAEMONS = get_btest_int("BTEST_N_DAEMONS")
BSTORE = BTEST_VARS.get("BSTORE", "store")


syslog_time_regex = re.compile("(\\d{4})-(\\d{2})-(\\d{2})T\
(\\d{2}):(\\d{2}):(\\d{2})\\.(\\d{6})")
syslog_hdr = re.compile("(\\d{4})-(\\d{2})-(\\d{2})T\
(\\d{2}):(\\d{2}):(\\d{2})\\.(\\d{6})([+-]\\d+:\\d+) (\\w+)")

def parse_local_time(_str):
    m = syslog_time_regex.match(_str)
    t = [ int(x) for x in m.groups() ]
    micro = t[6]
    t = t[:6]
    t.append(0)
    t.append(0)
    t.append(-1)
    ts = time.mktime(t)
    return ts + float(micro)/(10**6)


def parse_hdr(_str):
    m = syslog_hdr.match(_str)
    t = [ int(x) for x in m.group(*range(1,8)) ]
    micro = t[6]
    t = t[:6]
    t.append(0)
    t.append(0)
    t.append(-1)
    ts = time.mktime(t) + float(micro)/(10**6)
    return (ts, m.group(9))


def get_test_patterns():
    out = subprocess.check_output("source config.sh; ./gen-ptns.pl",
                                  shell=True, executable="/bin/bash")
    sio = StringIO(out)
    return [
        "<hostname> " + \
        str(s.rstrip().decode('utf-8').replace(u"\u2022", "<dec>")) for s in sio
    ]

PTN_TOKENIZER = re.compile("<hostname>|<dec>|\\w+|\\W")
PTN_TKN_VAR = re.compile("^(:?<hostname>|<dec>)$")

class TestPtnEntry(object):
    __slots__ = ('count', 'ptn_tkn', 'text', 'regex', 'hist', 'comp_hist', 'var_pos')

    def __init__(self, text, regex=None):
        self.count = 0
        self.ptn_tkn = {}
        self.text = text
        self.regex = re.compile(regex) if regex else None
        self.hist = {}
        self.comp_hist = {}
        self.var_pos = set()
        # variable positions
        pos = 0
        for s in PTN_TOKENIZER.findall(text):
            if PTN_TKN_VAR.match(s):
                self.var_pos.add(pos)
            pos += 1

    def add_ptn_tkn(self, pos, tkn_text):
        if pos not in self.var_pos:
            return
        key = (pos, tkn_text)
        try:
            self.ptn_tkn[key] += 1
        except KeyError:
            self.ptn_tkn[key] = 1

    def add_hist(self, bin_width, ts):
        _ts = int(ts)/int(bin_width)*int(bin_width)
        key = (bin_width, _ts)
        try:
            self.hist[key] += 1
        except KeyError:
            self.hist[key] = 1

    def add_comp_hist(self, bin_width, ts, comp):
        _ts = int(ts)/int(bin_width)*int(bin_width)
        key = (bin_width, _ts, comp, self.text)
        try:
            self.comp_hist[key] += 1
        except KeyError:
            self.comp_hist[key] = 1


def get_messages():
    cmd = "source config.sh; ./gen-log.pl 2>/dev/null"
    out = subprocess.check_output(cmd, shell=True, executable="/bin/bash")
    sio = StringIO(out)
    return [ line.rstrip() for line in sio ]


def get_ptn_stats():
    out = subprocess.check_output("source config.sh; ./gen-ptns.pl",
                                  shell=True, executable="/bin/bash")
    sio = StringIO(out)
    tokenizer = re.compile("\\w+|\\W")
    ptns = {}
    for s in sio:
        u = s.rstrip().decode('utf-8')
        k = str("<hostname> " + u.replace(u"\u2022", "<dec>"))
        m = str(".* \\w+ " + u.replace(u"\u2022", "\\d+") )
        assert(k not in ptns)
        ptns[k] = TestPtnEntry(k, m)
    for line in get_messages():
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


_tkn_re_table = [
    (re.compile("^node[0-9]+$"), Bq.BTKN_TYPE_HOSTNAME),
    (re.compile("^[0-9]+$"), Bq.BTKN_TYPE_DEC_INT),
    (re.compile("^(0x)?[0-9A-Fa-f]+$"), Bq.BTKN_TYPE_HEX_INT),
]

def get_tkn_type(_str):
    # This function only determine types with simple matching
    for (r, t) in _tkn_re_table:
        m = r.match(_str)
        if m:
            return t
    return 0


def get_tkn_hist(bin_width = 3600, ts_start = 0, tkn_text = None):
    hist = {} # key: bin_width, time, tkn_text, value: count
    tokenizer = re.compile("\\w+|\\W")
    for line in get_messages():
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


def get_tkn_stat(tkn):
    cmd = "source config.sh; ./gen-log.pl 2>/dev/null" + \
          " | grep -o '\\<%s\\>' | wc -l" % tkn
    out = subprocess.check_output(cmd, shell=True, executable="/bin/bash")
    return int(out)


ptn_tkn_text_tbl = {
    Bq.BTKN_TYPE_TYPE: "<type>",
    Bq.BTKN_TYPE_PRIORITY: "<priority>",
    Bq.BTKN_TYPE_VERSION: "<version>",
    Bq.BTKN_TYPE_TIMESTAMP: "<timestamp>",
    Bq.BTKN_TYPE_HOSTNAME: "<hostname>",
    Bq.BTKN_TYPE_SERVICE: "<service>",
    Bq.BTKN_TYPE_PID: "<pid>",
    Bq.BTKN_TYPE_IP4_ADDR: "<ip4>",
    Bq.BTKN_TYPE_IP6_ADDR: "<ip6>",
    Bq.BTKN_TYPE_ETH_ADDR: "<eth>",
    Bq.BTKN_TYPE_HEX_INT: "<hex>",
    Bq.BTKN_TYPE_DEC_INT: "<dec>",
    Bq.BTKN_TYPE_FLOAT: "<float>",
    Bq.BTKN_TYPE_PATH: "<path>",
    Bq.BTKN_TYPE_URL: "<url>",
    Bq.BTKN_TYPE_WORD: "<word>",
    Bq.BTKN_TYPE_SEPARATOR: "<sep>",
    Bq.BTKN_TYPE_WHITESPACE: " ",
    Bq.BTKN_TYPE_TEXT: "\u2022",
}


def PTN(_ptn):
    if _ptn:
        return Ptn(_ptn)
    return None

def PTN_ATTR(_ptn_attr):
    if _ptn_attr:
        return PtnAttr(_ptn_attr)
    return None


def TKN(_tkn):
    if _tkn:
        return Tkn(_tkn)
    return None


def TKN_HIST(th):
    if th:
        return TknHist(th)
    return None


def PTN_HIST(th):
    if th:
        return PtnHist(th)
    return None


def COMP_HIST(th):
    if th:
        return CompHist(th)
    return None


def MSG(bs, _msg):
    if _msg:
        return Msg(bs, _msg)
    return None


class BStore(object):
    @classmethod
    def open(cls, plugin, path, flags, mode):
        bs = Bq.Bstore(plugin)
        bs.open(path, flags, mode)
        return BStore(bs, path)

    def __init__(self, bs, path):
        self.bs = bs
        self.path = path

    def close(self):
        self.bs.close()

    def __del__(self):
        del self.bs

    def tknFindByName(self, name):
        if not name:
            return None
        return TKN(self.bs.tkn_by_name(name))

    def tknFindById(self, _id):
        return TKN(self.bs.tkn_by_id(_id))

    def getTknId(self, _str):
        if not _str:
            return 0
        t = self.tknFindByName(_str)
        if t:
            return t.tkn_id
        return 0

    def getPtnId(self, _str):
        if not _str:
            return 0
        p = self.ptnFindByStr(_str)
        if p:
            return p.ptn_id
        return 0

    def ptnFindByStr(self, _str):
        if not _str:
            return None
        for ptn in PtnIter(self):
            if str(ptn) == _str:
                return ptn

    def ptnFindById(self, _id):
        assert(_id)
        return PTN(self.bs.ptn_by_id(_id))

    def attrNew(self, attr_type):
        self.bs.attr_new(attr_type)

    def attrFind(self, attr_type):
        return self.bs.attr_find(attr_type)

    def ptnAttrValueSet(self, ptn_id, attr_type, attr_value):
        return self.bs.ptn_attr_value_set(ptn_id, attr_type, attr_value)

    def ptnAttrGet(self, ptn_id, attr_type):
        return self.bs.ptn_attr_get(ptn_id, attr_type)

    def ptnAttrValueAdd(self, ptn_id, attr_type, attr_value):
        return self.bs.ptn_attr_value_add(ptn_id, attr_type, attr_value)

    def ptnAttrValueRm(self, ptn_id, attr_type, attr_value):
        return self.bs.ptn_attr_value_rm(ptn_id, attr_type, attr_value)

class Tkn(object):
    __slots__ = ('tkn_count', 'tkn_text', 'tkn_type_mask', 'tkn_id',
                 'tkn_first_type')

    def __init__(self, btkn):
        assert(type(btkn) == Bq.Btkn)
        self.tkn_count = btkn.tkn_count()
        self.tkn_text = btkn.tkn_str()
        self.tkn_type_mask = btkn.type_mask()
        self.tkn_id = btkn.tkn_id()
        tmp = self.tkn_type_mask >> 1 # skip the TYPE_TYPE
        first_type = 2
        while tmp:
            if tmp & 1:
                break
            tmp >>= 1
            first_type += 1
        self.tkn_first_type = first_type

    def __iadd__(self, other):
        if self.tkn_text != other.tkn_text:
            raise KeyError("Merging incompatible token text")
        self.tkn_count += other.tkn_count
        self.tkn_type_mask |= other.tkn_type_mask
        return self

    def __eq__(self, other):
        if other == None:
            return False
        return self.tkn_count == other.tkn_count and \
                self.tkn_text == other.tkn_text and \
                self.tkn_type_mask == other.tkn_type_mask and \
                self.tkn_id == other.tkn_id

    def __str__(self):
        return self.tkn_text

    def info(self):
        return "('%s', %d, %d, %d)" % (
                    self.ptn_text(),
                    self.tkn_id,
                    self.tkn_type_mask,
                    self.tkn_count
        )

    def ptn_text(self):
        if self.tkn_type_mask & TYPE_MASK(Bq.BTKN_TYPE_TYPE):
            return ptn_tkn_text_tbl[self.tkn_first_type]
        return self.tkn_text


class TknHist(object):
    __slots__ = ('tkn_id', 'bin_width', 'time', 'tkn_count')

    def __init__(self, bth):
        assert(bth)
        self.tkn_id = bth.tkn_id()
        self.bin_width = bth.bin_width()
        self.time = bth.time()
        self.tkn_count = bth.tkn_count()

    def __str__(self):
        return "%d %d %d %d" % (self.tkn_id, self.bin_width, self.time,
                                self.tkn_count)

    def __eq__(self, other):
        if other == None:
            return False
        return self.tkn_id == other.tkn_id and \
               self.bin_width == other.bin_width and \
               self.tkn_count == other.tkn_count and \
               self.time == other.time

    def __cmp__(self, other):
        if other == None:
            return 1
        if self.bin_width < other.bin_width:
            return -1
        if self.bin_width > other.bin_width:
            return 1
        if self.time < other.time:
            return -1
        if self.time > other.time:
            return 1
        if self.tkn_id < other.tkn_id:
            return -1
        if self.tkn_id > other.tkn_id:
            return 1
        if self.tkn_count < other.tkn_count:
            return -1
        if self.tkn_count > other.tkn_count:
            return 1
        return 0


class PtnHist(object):
    __slots__ = ('ptn_id', 'bin_width', 'time', 'msg_count')

    def __init__(self, bth):
        assert(bth)
        self.ptn_id = bth.ptn_id()
        self.bin_width = bth.bin_width()
        self.time = bth.time()
        self.msg_count = bth.msg_count()

    def __str__(self):
        return "%d %d %d %d" % (self.ptn_id, self.bin_width, self.time,
                                self.msg_count)

    def __eq__(self, other):
        if other == None:
            return False
        return self.ptn_id == other.ptn_id and \
               self.bin_width == other.bin_width and \
               self.msg_count == other.msg_count and \
               self.time == other.time

    def __cmp__(self, other):
        if other == None:
            return 1
        if self.bin_width < other.bin_width:
            return -1
        if self.bin_width > other.bin_width:
            return 1
        if self.time < other.time:
            return -1
        if self.time > other.time:
            return 1
        if self.ptn_id < other.ptn_id:
            return -1
        if self.ptn_id > other.ptn_id:
            return 1
        if self.msg_count < other.msg_count:
            return -1
        if self.msg_count > other.msg_count:
            return 1
        return 0


class CompHist(object):
    __slots__ = ('bin_width', 'time', 'comp_id', 'ptn_id', 'msg_count')

    def __init__(self, bth):
        assert(bth)
        self.bin_width = bth.bin_width()
        self.time = bth.time()
        self.comp_id = bth.comp_id()
        self.ptn_id = bth.ptn_id()
        self.msg_count = bth.msg_count()

    def __str__(self):
        return "%d %d %d %d %d" % (
                            self.bin_width,
                            self.time,
                            self.comp_id,
                            self.ptn_id,
                            self.msg_count
                        )

    def __eq__(self, other):
        if other == None:
            return False
        return self.bin_width == other.bin_width and \
                self.time == other.time and \
                self.comp_id == other.comp_id and \
                self.ptn_id == other.ptn_id and \
                self.msg_count == other.msg_count

    def __cmp__(self, other):
        if other == None:
            return 1
        if self.bin_width < other.bin_width:
            return -1
        if self.bin_width > other.bin_width:
            return 1
        if self.time < other.time:
            return -1
        if self.time > other.time:
            return 1
        if self.comp_id < other.comp_id:
            return -1
        if self.comp_id > other.comp_id:
            return 1
        if self.ptn_id < other.ptn_id:
            return -1
        if self.ptn_id > other.ptn_id:
            return 1
        if self.msg_count < other.msg_count:
            return -1
        if self.msg_count > other.msg_count:
            return 1
        return 0


class Ptn(object):
    __slots__ = ('count', 'ptn_id', 'tkn_list', 'first_seen', 'last_seen')

    def __init__(self, bptn=Bq.Bptn()):
        assert(type(bptn) == Bq.Bptn)
        self.count = bptn.msg_count()
        self.ptn_id = bptn.ptn_id()
        self.tkn_list = [Tkn(x) for x in bptn]
        self.first_seen = float(bptn.first_seen())
        self.last_seen = float(bptn.last_seen())

    def __str__(self):
        s = StringIO()
        for t in self.tkn_list:
            s.write(t.ptn_text())
        return s.getvalue()

    def info_str(self):
        s = StringIO()
        print >>s, "%d, %d, %f, %f, %s" % (
            self.ptn_id,
            self.count,
            self.first_seen,
            self.last_seen,
            str(self)
        )
        return s.getvalue()

    def __iadd__(self, other):
        if str(self) != str(other):
            raise KeyError("Invalid pattern merge")
        self.count += other.count
        if other.first_seen < self.first_seen:
            self.first_seen = other.first_seen
        if other.last_seen > self.last_seen:
            self.last_seen = other.last_seen

    def __eq__(self, other):
        if other == None:
            return False
        return self.ptn_id == other.ptn_id and \
                self.count == other.count and \
                self.first_seen == other.first_seen and \
                self.last_seen == other.last_seen and \
                len(self.tkn_list) == len(other.tkn_list) and \
                str(self) == str(other)


class PtnAttr(object):
    __slots__ = ("ptn_id", "attr_type", "attr_value")

    def __init__(self, ptn_attr = Bq.Bptn_attr()):
        assert(type(ptn_attr) == Bq.Bptn_attr)
        self.ptn_id = ptn_attr.ptn_id()
        self.attr_type = ptn_attr.attr_type()
        self.attr_value = ptn_attr.attr_value()

    def __str__(self):
        return "(%d, '%s', %s')" % (self.ptn_id, self.attr_type, self.attr_value)


class Msg(object):
    __slots__ = ('bs', 'ptn_id', 'timestamp', 'comp_id', 'host', 'tkn_list')

    def __init__(self, bs, bmsg):
        assert(bmsg)
        self.bs = bs
        self.comp_id = int(bmsg.comp_id())
        self.timestamp = float(bmsg.tv_sec() + bmsg.tv_usec()/1e6)
        self.ptn_id = int(bmsg.ptn_id())
        self.host = Tkn(bs.bs.tkn_by_id(bmsg.comp_id()))
        self.tkn_list = [Tkn(x) for x in bmsg]

    def __str__(self):
        return "%.06f %s %s" % (self.timestamp, self.host, self.text())

    def text(self):
        s = StringIO()
        for t in self.tkn_list:
            s.write(t.ptn_text())
        return s.getvalue()

    def info_str(self):
        s = StringIO()
        print >>s, "%d, %f, %d, %s, %s" % (
            self.ptn_id,
            self.timestamp,
            self.comp_id,
            self.host,
            self.text()
        )
        return s.getvalue()

    def msg(self):
        nano = int(round((self.timestamp % 1) * 10**6))
        tm = time.localtime(self.timestamp)
        tz = 3600*tm.tm_isdst - (time.timezone)
        tzh = tz/3600
        tzm = tz%3600
        tstr = time.strftime("%FT%T", tm)
        tstr += (".%06d%+.02d:%02d" % (nano, tzh, tzm))
        return "%s %s" % (tstr, self.text())

    def __eq__(self, other):
        if other == None:
            return False
        return self.ptn_id == other.ptn_id and \
                self.timestamp == other.timestamp and \
                self.comp_id == other.comp_id and \
                str(self.host) == str(other.host) and \
                len(self.tkn_list) == len(other.tkn_list) and \
                self.text() == other.text()


class Iter(object):
    def __init__(self, bs, **kwargs):
        raise NotImplemented("sub-class must override this!")
        # The sub-class must do the following:
        # - set `self.itr` in __init__
        # - define self.obj() method

    def __del__(self):
        del self.itr

    def set_filter(self, **kwargs):
        return self.itr.set_filter(**kwargs)

    def find_fwd(self, **kwargs):
        return self._step(self.itr.find_fwd, **kwargs)

    def find_rev(self, **kwargs):
        return self._step(self.itr.find_rev, **kwargs)

    def card(self):
        return self.itr.card()

    def _step(self, fn, *args, **kwargs):
        success = fn(*args, **kwargs)
        if success:
            return self.obj()
        return None

    def first(self):
        return self._step(self.itr.first)

    def last(self):
        return self._step(self.itr.last)

    def next(self):
        return self._step(self.itr.next)

    def prev(self):
        return self._step(self.itr.prev)

    def get_pos(self):
        return self.itr.get_pos()

    def set_pos(self, pos):
        return self.itr.set_pos(pos)

    def __iter__(self):
        obj = self.first()
        while obj:
            yield obj
            obj = self.next()


class TknIter(Iter):
    def __init__(self, bs):
        assert(type(bs) == BStore)
        self.itr = Bq.Btkn_iter(bs.bs)

    def obj(self):
        return TKN(self.itr.obj())


# Ptn_Iter wrapper. This is not a Python Iterator. However, it implements
# `__iter__()` so that it can be used as Python Iterator.
class PtnIter(Iter):
    def __init__(self, bs):
        assert(type(bs) == BStore)
        self.itr = Bq.Bptn_iter(bs.bs)

    def obj(self):
        return PTN(self.itr.obj())


class PtnAttrIter(Iter):
    def __init__(self, bs):
        assert(type(bs) == BStore)
        self.itr = Bq.Bptn_attr_iter(bs.bs)

    def obj(self):
        return PTN_ATTR(self.itr.obj())


class PtnTknIter(Iter):
    def __init__(self, bs, ptn_id, tkn_pos): # find-based
        assert(type(bs) == BStore)
        self.itr = Bq.Bptn_tkn_iter(bs.bs, ptn_id, tkn_pos)

    def obj(self):
        return TKN(self.itr.obj())


class MsgIter(Iter):
    def __init__(self, bs):
        assert(type(bs) == BStore)
        self.bs = bs
        self.itr = Bq.Bmsg_iter(bs.bs)

    def __del__(self):
        del self.itr

    def obj(self):
        return MSG(self.bs, self.itr.obj())

    def count(self, ptn_id, **kwargs):
        return self.itr.count(ptn_id, **kwargs)


class MsgIterFilter(MsgIter):
    def __init__(self, bs, tv_begin=(0,0), tv_end=(0,0), comp_id=0, ptn_id=0):
        super(MsgIterFilter, self).__init__(bs)
        self.key = dict(tv = tv_begin, tv_begin=tv_begin, tv_end=tv_end,
                        comp_id=comp_id, ptn_id=ptn_id)
        self.itr.set_filter(**self.key)

    def __iter__(self):
        msg = self.find_fwd(**self.key)
        while msg:
            yield msg
            msg = self.next()


class MsgRevIter(MsgIter):
    def __iter__(self):
        msg = self.last()
        while msg:
            yield msg
            msg = self.prev()


class TknHistIter(Iter):
    def __init__(self, bs, **kwargs):
        assert(type(bs) == BStore)
        self.itr = Bq.Btkn_hist_iter(bs.bs)
        self.itr.set_filter(**kwargs)
        assert(self.itr)

    def obj(self):
        return TKN_HIST(self.itr.obj())


class PtnHistIter(Iter):
    def __init__(self, bs, **kwargs):
        assert(type(bs) == BStore)
        self.itr = Bq.Bptn_hist_iter(bs.bs)
        self.itr.set_filter(**kwargs)
        assert(self.itr)

    def obj(self):
        return PTN_HIST(self.itr.obj())


class CompHistIter(Iter):
    def __init__(self, bs, **kwargs):
        assert(type(bs) == BStore)
        self.itr = Bq.Bcomp_hist_iter(bs.bs)
        self.itr.set_filter(**kwargs)
        assert(self.itr)

    def obj(self):
        return COMP_HIST(self.itr.obj())
