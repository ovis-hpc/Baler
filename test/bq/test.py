#!/usr/bin/env python

# This test file contains basic bq query test. For ptn_attr with bq command,
# please see `test/bq_ptn_attr/test.py`.

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
import subprocess

from StringIO import StringIO

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
TS_BEGIN = int(time.time()) / (24*3600) * (24*3600)
TS_END = TS_BEGIN + 24*3600
TS_INC = 600
HOST_NUM = 8
HOST_BASE = 1000

def HOSTS():
    for num in range(0, HOST_NUM):
        yield "host%05d" % num

# make host.list
with open(BALERD_HOST_LIST, "w") as f:
    for h, hid in zip(HOSTS(), range(0, HOST_NUM)):
        print >>f, h, HOST_BASE + hid

time.tzset()

def str_findall(needle, haystack):
    coll = []
    pos = haystack.find(needle)
    while pos > 0:
        coll.append(pos)
        pos = haystack.find(needle, pos+1)
    return coll

def ts_text(ts):
    tm = time.localtime(ts)
    tz = time.altzone if tm.tm_isdst else time.timezone
    if tz < 0:
        sign = '+'
        tz = -tz
    else:
        sign = '-'
    tz_hr = tz / 3600
    tz_min = (tz % 3600) / 60
    txt = time.strftime("%FT%T.000000", tm)
    txt += "%s%02d:%02d"%(sign, tz_hr, tz_min)
    return txt

def TS_RANGE():
    for ts in range(TS_BEGIN, TS_END, TS_INC):
        yield ts_text(ts)

class Msg(object):
    __slots__ = ["ts", "ts_text", "host", "body_text", "ptn"]
    def __init__(self, ts, ts_text, host, body_text, ptn):
        self.ts = ts
        self.ts_text = ts_text
        self.host = host
        self.body_text = body_text
        self.ptn = ptn

    def __str__(self):
        return self.ts_text + " " + self.host + " " + self.body_text

    def sock_msg(self):
        return "<1>1 " + str(self) + "\n"

    def host_msg(self):
        """<host> + <body_text>"""
        return self.host + " " + self.body_text

PATTERNS = [
    "Zero + Pattern + Zero:",
    "One + Pattern + One:",
    "Two + Two + Pattern + Two + Two:",
    "Three + Pattern + Three:",
    "Four + Pattern + Four:",
    "Five + Pattern + Five:",
    "Six + Pattern + Six:",
    "Seven + Pattern + Seven:",
    #"Internationalization + Internationalization + Internationalization + Pattern + Internationalization:",
]

MSG_COUNT = 0
PTN_COUNT = { ptn: 0 for ptn in PATTERNS }
PTN_LAST_SEEN = { ptn: 0 for ptn in PATTERNS }
PTN_FIRST_SEEN = { ptn: float('inf') for ptn in PATTERNS }
PTN_ID = { ptn: ptn_id for (ptn, ptn_id) \
                       in zip(PATTERNS, range(256, 256+len(PATTERNS))) }

def ptn_first_seen(ptn_idx = None, ptn_key = None):
    if ptn_idx == None:
        if not ptn_key:
            raise KeyError("ptn_idx and ptn_key were not given")
        ptn_idx = PATTERNS.index(ptn_key)
    return TS_BEGIN + ptn_idx * TS_INC

def ptn_last_seen(ptn_idx = None, ptn_key = None):
    if ptn_idx == None:
        if not ptn_key:
            raise KeyError("ptn_idx and ptn_key were not given")
        ptn_idx = PATTERNS.index(ptn_key)
    return TS_END - (len(PATTERNS) - ptn_idx ) * TS_INC

def MESSAGES(count = False):
    global MSG_COUNT
    global PTN_COUNT
    msg_count = 0
    ts_count = int(TS_END - TS_BEGIN + TS_INC - 1) / TS_INC
    ptn_count = len(PATTERNS)
    for ts in range(TS_BEGIN, TS_END, TS_INC):
        _ts_text = ts_text(ts)
        for h in HOSTS():
            ptn_idx = -1
            for ptn in PATTERNS:
                ptn_idx += 1
                if ts < ptn_first_seen(ptn_idx) or ptn_last_seen(ptn_idx) < ts:
                    continue
                yield Msg(ts, _ts_text, h, ptn + " " + str(msg_count), ptn)
                msg_count += 1
                if count:
                    MSG_COUNT = msg_count
                    PTN_COUNT[ptn] += 1
                    PTN_FIRST_SEEN[ptn] = min(PTN_FIRST_SEEN[ptn], ts)
                    PTN_LAST_SEEN[ptn]  = max(PTN_LAST_SEEN[ptn],  ts)

MAKE_STORE = True

log = logging.getLogger(__name__)

class Debug(object): pass

DEBUG = Debug()
D = DEBUG # short name

class icmd(object):
    """Interactive command"""
    def __init__(self, cmd = str()):
        self.proc = subprocess.Popen(cmd, shell=True,
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
        fd = self.proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        assert(self.is_running())
        self.poll = select.poll()
        self.poll.register(fd, select.POLLIN)

    def is_running(self):
        self.proc.poll()
        return self.proc.returncode == None

    def comm(self, text):
        sio = StringIO()
        text = text.rstrip()
        self.proc.stdin.write(text + "\n")
        while self.poll.poll(1000):
            data = self.proc.stdout.read(4096)
            sio.write(data)
        sio.seek(0)
        return [l.rstrip() for l in sio.readlines()]

    def term(self):
        if not self.is_running():
            return
        self.proc.stdin.close()
        self.proc.wait()

    def __del__(self):
        self.term()


class bclient(icmd):
    """Interactive bclient"""
    def __init__(self, path = None):
        cmd = "bclient"
        if path:
            cmd += " -p="+path
        super(bclient, self).__init__(cmd)


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
    count = 0
    for msg in MESSAGES(count = True):
        sock.send(msg.sock_msg())
    sock.close()
    time.sleep(2)
    log.info("Terminating balerd")
    balerd.terminate()

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
    DEBUG.bsents = ents
    return ents

def cmd(*args):
    text = " ".join(args)
    p = subprocess.Popen(text, shell=True, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT)
    (out, err) = p.communicate()
    return out

def bq_cmd(*args):
    _cmd = "bq " +  (" ".join(map(str, args)))
    out = cmd(_cmd)
    return out

class SlotObj(object):
    def __str__(self):
        sio = StringIO()
        sio.write('{')
        for k in self.__slots__:
            v = self.__getattribute__(k)
            sio.write("%s: '%s', " % (k, v))
        sio.write('}')
        return sio.getvalue()

    def __repr__(self):
        return str(self)

DATE_FMT = r'\d\d\d\d-\d\d-\d\d'
TIME_FMT = r'\d\d:\d\d:\d\d'

def parse_bq_ts(ts):
    return time.mktime(time.strptime(ts, r'%Y-%m-%d %H:%M:%S'))

def ts_to_bq(ts):
    """make `ts` in bq input format"""
    tm = time.localtime(ts)
    return time.strftime("'%Y/%m/%d %H:%M'", tm)

BQ_PTN_LINE = re.compile(
    r'\s*(\d+)\s+(\d+)\s+('+DATE_FMT+' '+TIME_FMT+r')\s+'
    r'('+DATE_FMT+' '+TIME_FMT+r')\s+<host> (.*) <dec>\n'
)

UND = '\x1b[4m'
RST = '\x1b[0m'

class BqPtn(SlotObj):
    __slots__ = ["ptn_id", "msg_count", "first_seen", "last_seen",
                 "ptn", "ptn_str", "underline_cols", "matched_tkns"]
    def __init__(self, line):
        """Create BqPtn from the bq output `line`"""
        m = BQ_PTN_LINE.match(line.replace(UND, '').replace(RST, ''))
        if not m:
            raise ValueError("Bad bq pattern line: %s" % line)
        (ptn_id, msg_count, first_seen, last_seen, ptn) = m.groups()
        self.ptn_id = int(ptn_id)
        self.msg_count = int(msg_count)
        DMY_HMS = r'%Y-%m-%d %H:%M:%S'
        self.first_seen = parse_bq_ts(first_seen)
        self.last_seen = parse_bq_ts(last_seen)
        self.ptn = ptn
        self.ptn_str = '<host> ' + ptn + ' <dec>'
        # process highlight columns in the line
        tmp = line.split('\x1b') # ESC
        assert(len(tmp) % 2 == 1) # expecting odd splits
        pos = len(tmp[0])
        und = tmp[1::2]
        rst = tmp[2::2]
        rngs = []
        matched_tkns = []
        for u, r in zip(und, rst):
            # expecting alternating underline - reset
            if not u.startswith("[4m"):
                raise ValueError("Expecting `underline` ANSI sequence")
            if not r.startswith("[0m"):
                raise ValueError("Expecting `reset` ANSI sequence")
            matched_tkns.append(u[3:])
            rng = range(pos, pos+len(u) - 3)
            rngs.append(rng) # range of cols that got underlined
            pos += len(u) + len(r) - 6 # update pos
        self.underline_cols = rngs
        self.matched_tkns = matched_tkns


BQ_MSG_LINE = re.compile(
    r'\s*(\d+)\s+(\S+)\s+('+DATE_FMT+' '+TIME_FMT+r')\s+'
    r'((\S+) (.*:) \d+)\n'
)

class BqMsg(SlotObj):
    __slots__ = ["ptn_id", "host", "ts", "msg", "ptn"]
    def __init__(self, line):
        m = BQ_MSG_LINE.match(line)
        if not m:
            raise ValueError("Bad bq msg line: %s" % line)
        (ptn_id, host0, ts, msg, host1, ptn) = m.groups()
        self.ptn_id = int(ptn_id)
        assert(host0 == host1)
        self.host = host0
        self.ts = parse_bq_ts(ts)
        self.msg = msg
        self.ptn = ptn


BQ_TKN_LINE = re.compile(
    r'\s*(\d+) (\S+| )?\s+(\d+) (.*)?\n'
)

class BqTkn(SlotObj):
    __slots__ = ["tkn_id", "tkn_str", "count", "types"]
    def __init__(self, line):
        m = BQ_TKN_LINE.match(line)
        if not m:
            raise ValueError("Bad bq tkn line :%s" % line)
        (tkn_id, tkn_str, count, types) = m.groups()
        self.tkn_id = int(tkn_id)
        self.tkn_str = tkn_str
        self.count = int(count)
        self.types = re.findall(r'(\S+| ) ', types)


BQ_PTN_HIST_LINE = re.compile(
    r'\s*(\d+)\s+('+DATE_FMT+' '+TIME_FMT+r')\s+(\d+)\s+(\d+)\n'
)

class BqPtnHist(SlotObj):
    __slots__ = ["ptn_id", "ts", "bin_width", "count"]
    def __init__(self, line):
        m = BQ_PTN_HIST_LINE.match(line)
        if not m:
            raise ValueError("Bad bq ptn hist line :%s" % line)
        (ptn_id, ts, bin_width, count) = m.groups()
        self.ptn_id = int(ptn_id)
        self.ts = parse_bq_ts(ts)
        self.bin_width = int(bin_width)
        self.count = int(count)

    def bseq(self, bsent):
        x = bsent # shorten it
        return  self.ptn_id     ==  x.ptn_id()     and \
                self.ts         ==  x.time()       and \
                self.bin_width  ==  x.bin_width()  and \
                self.count      ==  x.msg_count()

BQ_COMP_HIST_LINE = re.compile(
    r'\s*(\S+)\s+(\d+)\s+('+DATE_FMT+' '+TIME_FMT+r')\s+(\d+)\s+(\d+)\n'
)

class BqCompHist(SlotObj):
    __slots__ = ["host", "ptn_id", "ts", "bin_width", "count"]
    def __init__(self, line):
        m = BQ_COMP_HIST_LINE.match(line)
        if not m:
            raise ValueError("Bad bq comp hist line :%s" % line)
        (host, ptn_id, ts, bin_width, count) = m.groups()
        self.host = host
        self.ptn_id = int(ptn_id)
        self.ts = parse_bq_ts(ts)
        self.bin_width = int(bin_width)
        self.count = int(count)

    def bseq(self, bsent):
        x = bsent
        bs_host = str(get_bstore().tkn_by_id(x.comp_id()))
        return  self.ptn_id     ==  x.ptn_id()     and \
                self.host       ==  bs_host        and \
                self.ts         ==  x.time()       and \
                self.bin_width  ==  x.bin_width()  and \
                self.count      ==  x.msg_count()


BQ_TKN_HIST_LINE = re.compile(
    r'\s*(\d+)\s+(\S+)\s+('+DATE_FMT+' '+TIME_FMT+r')\s+(\d+)\s+(\d+)\n'
)

class BqTknHist(SlotObj):
    __slots__ = ["tkn_id", "tkn_text", "ts", "bin_width", "count"]
    def __init__(self, line):
        m = BQ_TKN_HIST_LINE.match(line)
        if not m:
            raise ValueError("Bad bq tkn hist line :%s" % line)
        (tkn_id, tkn_text, ts, bin_width, count) = m.groups()
        self.tkn_id = int(tkn_id)
        self.tkn_text = tkn_text
        self.ts = parse_bq_ts(ts)
        self.bin_width = int(bin_width)
        self.count = int(count)

    def bseq(self, bsent):
        x = bsent
        return  self.tkn_id     ==  x.tkn_id()     and \
                self.ts         ==  x.time()       and \
                self.bin_width  ==  x.bin_width()  and \
                self.count      ==  x.tkn_count()


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


class TestBq(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        log.info("------- setUpClass -------")
        if not MAKE_STORE:
            return
        shutil.rmtree(STORE_PATH, ignore_errors = True)
        make_store()
        log.info("------- setUpClass COMPLETED -------")

    @classmethod
    def tearDownClass(cls):
        log.info("------- tearDownClass -------")

    def test_001_bq_versrion(self):
        """bq -V"""
        ver = bq.version_get("bstore_sos")
        lines = bq_cmd("-V")
        r = re.compile(
            r"bq\n"
            r"  version: (.*)\n"
            r"  gitsha:  (.*)\n"
            r"plugin: (.*)\n"
            r"  version: (.*)\n"
            r"  gitsha:  (.*)\n"
        )
        m = r.match(lines)
        if not m:
            raise RuntimeError("bad `bq -V` output: %s" % lines)
        (bq_ver, bq_gitsha, plugin, plugin_ver, plugin_gitsha) = m.groups()
        self.assertEqual(bq_ver, bq.bversion())
        self.assertEqual(bq_gitsha, bq.bgitsha())
        self.assertEqual(plugin, "bstore_sos")
        self.assertEqual(plugin_ver, ver["plugin"]["version"])
        self.assertEqual(plugin_gitsha, ver["plugin"]["gitsha"])

    def test_002_bq_store_version(self):
        """bq -V -p STORE"""
        ver = bq.version_get("bstore_sos", STORE_PATH)
        lines = bq_cmd("-V", "-p", STORE_PATH)
        r = re.compile(
            r"bq\n"
            r"  version: (.*)\n"
            r"  gitsha:  (.*)\n"
            r"plugin: (.*)\n"
            r"  version: (.*)\n"
            r"  gitsha:  (.*)\n"
            r"store: (.*)\n"
            r"  version: (.*)\n"
            r"  gitsha:  (.*)\n"
        )
        m = r.match(lines)
        if not m:
            raise RuntimeError("bad `bq -V` output: %s" % lines)
        (bq_ver, bq_gitsha, plugin, plugin_ver, plugin_gitsha,
         store, store_ver, store_gitsha) = m.groups()
        self.assertEqual(bq_ver, bq.bversion())
        self.assertEqual(bq_gitsha, bq.bgitsha())
        self.assertEqual(plugin, "bstore_sos")
        self.assertEqual(plugin_ver, ver["plugin"]["version"])
        self.assertEqual(plugin_gitsha, ver["plugin"]["gitsha"])
        self.assertEqual(store, STORE_PATH)
        self.assertEqual(store_ver, ver["store"]["version"])
        self.assertEqual(store_gitsha, ver["store"]["gitsha"])

    def _bq_ptn_process(self, lines):
        lines = StringIO(lines).readlines()
        self.assertRegexpMatches(lines[0],
             r'Ptn Id\s+Msg Count\s+First Seen\s+Last Seen\s+Pattern\s*\n')
        self.assertRegexpMatches(lines[1], r'-+ -+ -+ -+ -+\n')
        self.assertEqual(lines[1], lines[-2])
        m = re.match(r'(\d+) Patterns\(s\) (\d+) Messages\(s\)', lines[-1])
        if not m:
            raise RuntimeError("Bad pattern summary line: " + lines[-1])
        del lines[-2:] # delete the footer
        del lines[:2]  # delete the header
        (rec, count) = map(int, m.groups())
        bqptns = [ BqPtn(l) for l in lines ]
        return (bqptns, rec, count)

    def test_003_bq_ptn(self):
        """bq -p STORE --ptn"""
        lines = bq_cmd("-p", STORE_PATH, "--ptn")
        (bqptns, ptn_count, msg_count) = self._bq_ptn_process(lines)
        global MSG_COUNT
        global PTN_COUNT
        self.assertEqual(msg_count, MSG_COUNT)
        self.assertEqual(ptn_count, len(PTN_COUNT))
        bs = get_bstore()
        for bqptn in bqptns:
            self.assertEqual(bqptn.ptn_id, PTN_ID[bqptn.ptn])
            self.assertEqual(bqptn.msg_count, PTN_COUNT[bqptn.ptn])
            self.assertEqual(bqptn.first_seen, PTN_FIRST_SEEN[bqptn.ptn])
            self.assertEqual(bqptn.last_seen, PTN_LAST_SEEN[bqptn.ptn])
            self.assertEqual(bqptn.ptn_str, str(bs.ptn_by_id(bqptn.ptn_id)))

    def _bq_msg_process(self, lines):
        lines = StringIO(lines).readlines()
        self.assertRegexpMatches(lines[0],
             r'Ptn Id\s+Component\s+Timestamp\s+Message\s*\n')
        self.assertRegexpMatches(lines[1], r'-+ -+ -+ -+\n')
        self.assertEqual(lines[1], lines[-2])
        m = re.match(r'(\d+) Record\(s\)\n', lines[-1])
        if not m:
            raise RuntimeError("Bad message summary line: %s" % lines[-1])
        del lines[-2:] # delete the footer
        del lines[:2]  # delete the header
        (count,) = map(int, m.groups())
        bqmsgs = [ BqMsg(l) for l in lines ]
        self.assertEqual(len(bqmsgs), count)
        return (bqmsgs, count)

    def test_004_bq_msg(self):
        """bq -p STORE --msg"""
        lines = bq_cmd("-p", STORE_PATH, "--msg")
        (bqmsgs, count) = self._bq_msg_process(lines)
        self.assertEqual(count, MSG_COUNT)
        self.assertEqual(len(bqmsgs), MSG_COUNT)
        for bqm, m in zip(bqmsgs, MESSAGES()):
            self.assertEqual(bqm.ptn_id, PTN_ID[bqm.ptn])
            self.assertEqual(bqm.host, m.host)
            self.assertEqual(bqm.ts, m.ts)
            self.assertEqual(bqm.msg, m.host_msg())

    def _bq_tkn_process(self, lines):
        lines = StringIO(lines).readlines()
        self.assertRegexpMatches(lines[0],
             r'Tkn Id\s+Tkn String\s+Tkn Seen\s+Types\s*\n')
        self.assertRegexpMatches(lines[1], r'-+ -+ -+ -+\n')
        self.assertEqual(lines[1], lines[-2])
        m = re.match(r'(\d+) Record\(s\)\n', lines[-1])
        if not m:
            raise RuntimeError("Bad tkn summary line: %s" % lines[-1])
        del lines[-2:] # delete the footer
        del lines[:2]  # delete the header
        (count,) = map(int, m.groups())
        bqtkns = [ BqTkn(l) for l in lines ]
        return (bqtkns, count)

    def test_005_bq_tkn(self):
        """bq -p STORE --tkn"""
        lines = bq_cmd("-p", STORE_PATH, "--tkn")
        (bqtkns, count) = self._bq_tkn_process(lines)
        bs = get_bstore()
        tkns = [ t for t in bq.Btkn_iter(bs) ]
        self.assertEqual(count, len(bqtkns))
        self.assertEqual(count, len(tkns))
        for bqtkn, t in zip(bqtkns, tkns):
            self.assertEqual(bqtkn.tkn_id, t.tkn_id())
            self.assertEqual(bqtkn.tkn_str.strip(), str(t).strip())
            self.assertEqual(bqtkn.count, t.tkn_count())
            self.assertEqual(set(bqtkn.types),
                             set( bs.tkn_type_str(b) for b in t ))

    def _bq_ptn_hist_process(self, lines):
        lines = StringIO(lines).readlines()
        self.assertRegexpMatches(lines[0],
             r'Ptn Id\s+Timestamp\s+Bin Width\s+Msg Count\s*\n')
        self.assertRegexpMatches(lines[1], r'-+ -+ -+ -+\n')
        self.assertEqual(lines[1], lines[-2])
        m = re.match(r'(\d+) Record\(s\)\s+(\d+)\n', lines[-1])
        if not m:
            raise RuntimeError("Bad ptn_hist summary line: %s" % lines[-1])
        del lines[-2:]
        del lines[:2]
        (rec, count) = map(int, m.groups())
        ents = [ BqPtnHist(l) for l in lines ]
        return (ents, rec, count)

    def test_006_bq_ptn_hist(self):
        """bq -p STORE --hist --ptn"""
        lines = bq_cmd("-p", STORE_PATH, "--hist", "--ptn")
        (ents, rec, total_count) = self._bq_ptn_hist_process(lines)
        bs = get_bstore()
        itr = bq.Bptn_hist_iter(bs)
        itr.set_filter(bin_width=60)
        hists = [ h for h in itr ]
        _sum = 0
        for e, h in zip(ents, hists):
            self.assertEqual(e.ptn_id, h.ptn_id())
            self.assertEqual(e.ts, h.time())
            self.assertEqual(e.bin_width, h.bin_width())
            self.assertEqual(e.count, h.msg_count())
            _sum += e.count
        self.assertEqual(_sum, total_count)

    def _bq_comp_hist_process(self, lines):
        lines = StringIO(lines).readlines()
        self.assertRegexpMatches(lines[0],
             r'Component\s+Ptn Id\s+Timestamp\s+Bin Width\s+Msg Count\s*\n')
        self.assertRegexpMatches(lines[1], r'-+ -+ -+ -+ -+\n')
        self.assertEqual(lines[1], lines[-2])
        m = re.match(r'(\d+) Record\(s\)\s+(\d+)\n', lines[-1])
        if not m:
            raise RuntimeError("Bad comp_hist summary line: %s" % lines[-1])
        del lines[-2:]
        del lines[:2]
        (rec, count) = map(int, m.groups())
        ents = [ BqCompHist(l) for l in lines ]
        return (ents, rec, count)

    def test_007_bq_comp_hist(self):
        """bq -p STORE --hist --comp"""
        lines = bq_cmd("-p", STORE_PATH, "--hist", "--comp")
        (ents, rec, total_count) = self._bq_comp_hist_process(lines)
        bs = get_bstore()
        itr = bq.Bcomp_hist_iter(bs)
        itr.set_filter(bin_width=60)
        hists = [ h for h in itr ]
        _sum = 0
        for e, h in zip(ents, hists):
            self.assertEqual(e.host, str(bs.tkn_by_id(h.comp_id())))
            self.assertEqual(e.ptn_id, h.ptn_id())
            self.assertEqual(e.ts, h.time())
            self.assertEqual(e.bin_width, h.bin_width())
            self.assertEqual(e.count, h.msg_count())
            _sum += e.count
        self.assertEqual(_sum, total_count)

    def _bq_tkn_hist_process(self, lines):
        lines = StringIO(lines).readlines()
        self.assertRegexpMatches(lines[0],
             r'Tkn Id\s+Tkn Text\s+Timestamp\s+Bin Width\s+Msg Count\s*\n')
        self.assertRegexpMatches(lines[1], r'-+ -+ -+ -+ -+\n')
        self.assertEqual(lines[1], lines[-2])
        m = re.match(r'(\d+) Record\(s\)\s+(\d+)\n', lines[-1])
        if not m:
            raise RuntimeError("Bad tkn_hist summary line: %s" % lines[-1])
        del lines[-2:]
        del lines[:2]
        (rec, count) = map(int, m.groups())
        ents = [ BqTknHist(l) for l in lines ]
        return (ents, rec, count)

    def test_008_bq_tkn_hist_filter(self):
        """bq -p STORE --hist --tkn --tkn_str Pattern"""
        tkn_name = "Pattern"
        lines = bq_cmd("-p", STORE_PATH, "--hist", "--tkn",
                       "--tkn_str", tkn_name)
        (ents, rec, total_count) = self._bq_tkn_hist_process(lines)
        bs = get_bstore()
        tkn = bs.tkn_by_name(tkn_name)
        itr = bq.Btkn_hist_iter(bs)
        itr.set_filter(bin_width=60, tkn_id=tkn.tkn_id())
        hists = [ h for h in itr ]
        _sum = 0
        for e, h in zip(ents, hists):
            self.assertEqual(e.tkn_id, h.tkn_id())
            self.assertEqual(e.tkn_text, str(bs.tkn_by_id(h.tkn_id())))
            self.assertEqual(e.ts, h.time())
            self.assertEqual(e.bin_width, h.bin_width())
            self.assertEqual(e.count, h.tkn_count())
            _sum += e.count
        self.assertEqual(_sum, total_count)

    def test_009_bq_ptn_tkn(self):
        """bq -p STORE --ptn_tkn --tkn_id"""
        bs = get_bstore()
        ptn_id = 256
        ptn = bs.ptn_by_id(ptn_id)
        lines = bq_cmd("-p", STORE_PATH, "--ptn_tkn", "--ptn_id", ptn_id)
        sio = StringIO(lines)
        hdr0 = sio.readline()
        DEBUG.hdr0 = hdr0
        m = re.match(r'Ptn Id: (\d+)\s+(.*)', hdr0)
        if not m:
            raise ValueError("Bad ptn_tkn heading line: %s" % hdr0)
        (_ptn_id, _ptn_text) = m.groups()
        _ptn_id = int(_ptn_id)
        _ptn_text = _ptn_text.strip()
        self.assertEqual(_ptn_id, ptn_id)
        self.assertEqual(_ptn_text, str(ptn))

        hdr1 = sio.readline()
        pos = map(int, re.findall('\d+', hdr1))
        _len = len([ x for x in ptn ])
        self.assertEqual(set(pos), set(range(0, _len)))

        hdr2 = sio.readline()
        dashes = re.findall('-+', hdr2)
        self.assertEqual(len(dashes), _len)
        cwidths = map(len, dashes)

        lines = sio.readlines()
        self.assertEqual(lines[-3].strip(), '')
        self.assertEqual(lines[-2], hdr2)
        counts = map(int, re.findall(r'\d+', lines[-1]))
        self.assertTrue(len(counts), _len)
        del lines[-3:]

        pos_tkns = [list() for x in range(0, _len)]
        for l in lines:
            ents = parse_bq_ptn_tkn(l, cwidths)
            for coll, ent in zip(pos_tkns, ents):
                if ent:
                    coll.append(ent)
        DEBUG.pos_tkns = pos_tkns
        _pos_tkns = [
            [str(t) for t in bq.Bptn_tkn_iter(bs, ptn_id=ptn_id, tkn_pos=pos)] \
            for pos in range(0, _len)
        ]
        DEBUG._pos_tkns = _pos_tkns
        for a, b in zip(pos_tkns, _pos_tkns):
            self.assertEqual(set(a), set(b))

    ##### bq with filtering #####

    def test_010_bq_ptn_ptn_id(self):
        """bq -p STORE --ptn --ptn_id 258"""
        lines = bq_cmd("-p", STORE_PATH, "--ptn", "--ptn_id", "258")
        (bqptns, ptn_count, msg_count) = self._bq_ptn_process(lines)
        self.assertEqual(len(bqptns), 1)
        self.assertEqual(ptn_count, 1)
        for bqptn in bqptns:
            self.assertEqual(bqptn.ptn_id, PTN_ID[bqptn.ptn])
            self.assertEqual(bqptn.msg_count, PTN_COUNT[bqptn.ptn])
            self.assertEqual(bqptn.first_seen, PTN_FIRST_SEEN[bqptn.ptn])
            self.assertEqual(bqptn.last_seen, PTN_LAST_SEEN[bqptn.ptn])
        self.assertEqual(bqptn.msg_count, msg_count)

    def test_011_bq_ptn_ptn_ids(self):
        """bq -p STORE --ptn --ptn_ids 257-260,263"""
        lines = bq_cmd("-p", STORE_PATH, "--ptn", "--ptn_ids", "257-260,263")
        ptn_ids = set([257, 258, 259, 260, 263])
        (bqptns, ptn_count, msg_count) = self._bq_ptn_process(lines)
        self.assertEqual(len(bqptns), len(ptn_ids))
        self.assertEqual(ptn_count, len(ptn_ids))
        _sum = 0
        for bqptn in bqptns:
            self.assertEqual(bqptn.ptn_id, PTN_ID[bqptn.ptn])
            self.assertEqual(bqptn.msg_count, PTN_COUNT[bqptn.ptn])
            self.assertEqual(bqptn.first_seen, PTN_FIRST_SEEN[bqptn.ptn])
            self.assertEqual(bqptn.last_seen, PTN_LAST_SEEN[bqptn.ptn])
            _sum += bqptn.msg_count
            ptn_ids.remove(bqptn.ptn_id)
        self.assertEqual(len(ptn_ids), 0)
        self.assertEqual(msg_count, _sum)

    def _bq_ptn_match(self, tkn_str):
        bs = get_bstore()
        bsents = get_matched_ptns(bs, tkn_str)
        lines = bq_cmd("-p", STORE_PATH, "--ptn",
                       "--match", "--tkn_str", tkn_str)
        lines = StringIO(lines).readlines()
        self.assertRegexpMatches(lines[0],
             r'Ptn Id\s+Msg Count\s+First Seen\s+Last Seen\s+Pattern\s*\n')
        self.assertRegexpMatches(lines[1], r'-+ -+ -+ -+ -+\n')
        self.assertEqual(lines[1], lines[-2])
        m = re.match(r'(\d+) Record\(s\)', lines[-1])
        if not m:
            raise RuntimeError("Bad pattern match summary line: " + lines[-1])
        (rec,) = map(int, m.groups())
        del lines[-2:]
        del lines[:2]
        ptn_lines = lines[0::2]
        loc_lines = lines[1::2]
        bqents = []
        for ptn_line, loc_line in zip(ptn_lines, loc_lines):
            bqptn = BqPtn(ptn_line)
            DEBUG.bqptn = bqptn
            DEBUG.ptn_line = ptn_line
            coll = str_findall('^', loc_line)
            # verifying locators
            self.assertEqual(len(coll), len(bqptn.underline_cols))
            for pos, rng in zip(coll, bqptn.underline_cols):
                self.assertIn(pos, rng)
            bqents.append(bqptn)
        self.assertEqual(len(bqents), len(bsents))
        for bse, bqe in zip(bsents, bqents):
            (ptn, pos) = bse
            tkns = [ t for t in ptn ]
            _tkns = [ tkns[i].ptn_tkn_str() for i in pos ]
            self.assertEqual(_tkns, bqe.matched_tkns)
        log.debug("----- entries -----")
        log.debug(bqents)
        log.debug(bsents)
        log.debug("-------------------")

    def test_012_bq_ptn_match_zero(self):
        """bq -p STORE --ptn --match --tkn_str Three"""
        self._bq_ptn_match("Three")

    def test_013_bq_ptn_match_10(self):
        """bq -p STORE --ptn --match --tkn_str 10"""
        self._bq_ptn_match("10")

    def test_014_bq_ptn_match_Pattern(self):
        """bq -p STORE --ptn --match --tkn_str Pattern"""
        self._bq_ptn_match("Pattern")

    def test_015_bq_ptn_match_plus(self):
        """bq -p STORE --ptn --match --tkn_str '+'"""
        self._bq_ptn_match("+")

    def test_016_bq_ptn_match_host00001(self):
        """bq -p STORE --ptn --match --tkn_str host00001"""
        self._bq_ptn_match("host00001")

    def _bq_msg_filter(self, *args):
        lines = bq_cmd("-p", STORE_PATH, "--msg", *args)
        (bqmsgs, count) = self._bq_msg_process(lines)
        return (bqmsgs, count)

    def _bs_msg_filter(self, **kwargs):
        bs = get_bstore()
        itr = bq.Bmsg_iter(bs)
        itr.set_filter(**kwargs)
        return [ m for m in itr ]

    def _bq_bs_msg_cmp(self, bqmsgs, bsmsgs):
        bs = get_bstore()
        self.assertEqual(len(bqmsgs), len(bsmsgs))
        for q, s in zip(bqmsgs, bsmsgs):
            self.assertEqual(q.ptn_id, s.ptn_id())
            self.assertEqual(q.host, str(bs.tkn_by_id(s.comp_id())))
            self.assertEqual(q.ts, s.tv_sec())
            smsg = ''.join( [str(t) for t in s] )
            self.assertEqual(q.msg, smsg)

    def test_017_bq_msg_limit(self):
        """bq -p STORE --msg --limit 8"""
        (bqmsgs, count) = self._bq_msg_filter("--limit", 8)
        bsmsgs = self._bs_msg_filter()[:8]
        self._bq_bs_msg_cmp(bqmsgs, bsmsgs)

    def test_018_bq_msg_ptn_id(self):
        """bq -p STORE --msg --ptn_id 258"""
        (bqmsgs, count) = self._bq_msg_filter("--ptn_id", 258)
        bsmsgs = self._bs_msg_filter(ptn_id = 258)
        self._bq_bs_msg_cmp(bqmsgs, bsmsgs)

    def test_019_bq_msg_comp_id(self):
        """bq -p STORE --msg --comp_id 1005"""
        (bqmsgs, count) = self._bq_msg_filter("--comp_id", 1005)
        bsmsgs = self._bs_msg_filter(comp_id = 1005)
        self._bq_bs_msg_cmp(bqmsgs, bsmsgs)

    def test_020_bq_msg_comp_str(self):
        """bq -p STORE --msg --comp_str host00005"""
        comp_str = "host00005"
        comp_id = HOST_BASE + 5
        (bqmsgs, count) = self._bq_msg_filter("--comp_str", comp_str)
        bsmsgs = self._bs_msg_filter(comp_id = comp_id)
        self._bq_bs_msg_cmp(bqmsgs, bsmsgs)

    def test_021_bq_msg_begin(self):
        """bq -p STORE --msg --begin TIME"""
        ts = TS_END - 3 * TS_INC
        ts_text = ts_to_bq(ts)
        (bqmsgs, count) = self._bq_msg_filter("--begin", ts_text)
        bsmsgs = self._bs_msg_filter(tv_begin = (ts, 0))
        self._bq_bs_msg_cmp(bqmsgs, bsmsgs)

    def test_022_bq_msg_end(self):
        """bq -p STORE --msg --end TIME"""
        ts = TS_BEGIN + 3 * TS_INC
        ts_text = ts_to_bq(ts)
        (bqmsgs, count) = self._bq_msg_filter("--end", ts_text)
        bsmsgs = self._bs_msg_filter(tv_end = (ts, 0))
        self._bq_bs_msg_cmp(bqmsgs, bsmsgs)

    def test_023_bq_msg_mixed(self):
        """bq -p STORE --msg --begin T0 --end T1 --ptn_id 258 --comp_id 1005"""
        ts0 = TS_BEGIN + 3 * TS_INC
        ts0_text = ts_to_bq(ts0)
        ts1 = ts0 + 4 * TS_INC
        ts1_text = ts_to_bq(ts1)
        ptn_id = 258
        comp_id = 1005
        (bqmsgs, count) = self._bq_msg_filter(
                                "--begin",    ts0_text,
                                "--end",      ts1_text,
                                "--ptn_id",   ptn_id,
                                "--comp_id",  comp_id,
                            )
        bsmsgs = self._bs_msg_filter(
                        tv_begin = (ts0, 0),
                        tv_end   = (ts1, 0),
                        ptn_id   = ptn_id,
                        comp_id  = comp_id,
                    )
        self._bq_bs_msg_cmp(bqmsgs, bsmsgs)

    def test_024_bq_tkn_type_hostname(self):
        """bq -p STORE --tkn --tkn_type HOSTNAME"""
        lines = bq_cmd("-p", STORE_PATH, "--tkn", "--tkn_type", "HOSTNAME")
        (bqtkns, count) = self._bq_tkn_process(lines)
        bs = get_bstore()
        tkns = filter(lambda t: t.has_type(bq.BTKN_TYPE_HOSTNAME) ,
                      (t for t in bq.Btkn_iter(bs)))
        self.assertEqual(len(bqtkns), len(tkns))
        for q, s in zip(bqtkns, tkns):
            self.assertEqual(q.tkn_id, s.tkn_id())
            self.assertEqual(q.tkn_str, str(s))
            self.assertEqual(q.count, s.tkn_count())
            self.assertEqual(set(q.types),
                             set( bs.tkn_type_str(b) for b in s ))

    def _bq_hist(self, hist_type, *args):
        lines = bq_cmd("-p", STORE_PATH, "--hist", "--"+hist_type, *args)
        call_table = {
            "tkn"  : self._bq_tkn_hist_process,
            "ptn"  : self._bq_ptn_hist_process,
            "comp" : self._bq_comp_hist_process,
        }
        call = call_table[hist_type]
        # (ents, rec, count)
        (ents, rec, count) = call(lines)
        DEBUG.bqents = ents
        return (ents, rec, count)

    def _bs_hist(self, hist_type, **kwargs):
        return bs_hist(hist_type, **kwargs)

    def _bq_bs_hist_cmp(self, bqents, bsents):
        self.assertEqual(len(bqents), len(bsents))
        for q, s in zip(bqents, bsents):
            self.assertTrue(q.bseq(s))

    def test_025_bq_tkn_hist_begin(self):
        """bq -p STORE --hist --tkn --tkn_str Two --begin T0"""
        bs = get_bstore()
        tkn_str = "Two"
        tkn_id  = bs.tkn_by_name(tkn_str).tkn_id()
        ts = TS_BEGIN + 2 * TS_INC
        ts_txt = ts_to_bq(ts)
        D.ts = ts
        D.ts_txt = ts_txt
        D.tkn_id = tkn_id
        (bqents, rec, count) = self._bq_hist("tkn", "--tkn_str", tkn_str,
                                                    "--begin", ts_txt)
        bsents = self._bs_hist("tkn", tkn_id = tkn_id, tv_begin = (ts, 0))
        self._bq_bs_hist_cmp(bqents, bsents)

    def test_026_bq_ptn_hist_begin(self):
        """bq -p STORE --hist --ptn --ptn_id 256 --begin T0"""
        ptn_id = 256
        ts = TS_BEGIN + 2 * TS_INC
        ts_txt = ts_to_bq(ts)
        (bqents, rec, count) = self._bq_hist("ptn", "--ptn_id", ptn_id,
                                                    "--begin", ts_txt)
        bsents = self._bs_hist("ptn", ptn_id = ptn_id, tv_begin = (ts, 0))
        self._bq_bs_hist_cmp(bqents, bsents)

    def test_027_bq_comp_hist_begin(self):
        """bq -p STORE --hist --comp --ptn_id 256 --begin T0"""
        ptn_id = 256
        ts = TS_BEGIN + 2 * TS_INC
        ts_txt = ts_to_bq(ts)
        (bqents, rec, count) = self._bq_hist("comp", "--ptn_id", ptn_id,
                                                     "--begin", ts_txt)
        bsents = self._bs_hist("comp", ptn_id = ptn_id, tv_begin = (ts, 0))
        self._bq_bs_hist_cmp(bqents, bsents)

    def test_028_bq_tkn_hist_end(self):
        """bq -p STORE --hist --tkn --tkn_str Two --end T0"""
        bs = get_bstore()
        tkn_str = "Two"
        tkn_id  = bs.tkn_by_name(tkn_str).tkn_id()
        ts = TS_BEGIN + 4 * TS_INC
        ts_txt = ts_to_bq(ts)
        (bqents, rec, count) = self._bq_hist("tkn", "--tkn_str", tkn_str,
                                                    "--end", ts_txt)
        bsents = self._bs_hist("tkn", tkn_id = tkn_id, tv_end = (ts, 0))
        self._bq_bs_hist_cmp(bqents, bsents)

    def test_029_bq_ptn_hist_end(self):
        """bq -p STORE --hist --ptn --ptn_id 256 --end T0"""
        ptn_id = 256
        ts = TS_BEGIN + 4 * TS_INC
        ts_txt = ts_to_bq(ts)
        (bqents, rec, count) = self._bq_hist("ptn", "--ptn_id", ptn_id,
                                                    "--end", ts_txt)
        bsents = self._bs_hist("ptn", ptn_id = ptn_id, tv_end = (ts, 0))
        self._bq_bs_hist_cmp(bqents, bsents)

    def test_030_bq_comp_hist_end(self):
        """bq -p STORE --hist --comp --ptn_id 256 --end T0"""
        ptn_id = 256
        ts = TS_BEGIN + 4 * TS_INC
        ts_txt = ts_to_bq(ts)
        (bqents, rec, count) = self._bq_hist("comp", "--ptn_id", ptn_id,
                                                     "--end", ts_txt)
        bsents = self._bs_hist("comp", ptn_id = ptn_id, tv_end = (ts, 0))
        self._bq_bs_hist_cmp(bqents, bsents)

    def test_031_bq_tkn_hist_begin_end(self):
        """bq -p STORE --hist --tkn --tkn_str Two --begin T0 --end T1"""
        bs = get_bstore()
        tkn_str = "Two"
        tkn_id  = bs.tkn_by_name(tkn_str).tkn_id()
        ts0 = TS_BEGIN + 4 * TS_INC
        ts0_txt = ts_to_bq(ts0)
        ts1 = ts0 + 4 * TS_INC
        ts1_txt = ts_to_bq(ts1)
        (bqents, rec, count) = self._bq_hist("tkn", "--tkn_str", tkn_str,
                                                    "--begin", ts0_txt,
                                                    "--end", ts1_txt)
        bsents = self._bs_hist("tkn", tkn_id = tkn_id,
                                      tv_begin = (ts0, 0),
                                      tv_end = (ts1, 0))
        self._bq_bs_hist_cmp(bqents, bsents)

    def test_032_bq_ptn_hist_begin_end(self):
        """bq -p STORE --hist --ptn --ptn_id 256 --end T0"""
        ptn_id = 256
        ts0 = TS_BEGIN + 4 * TS_INC
        ts0_txt = ts_to_bq(ts0)
        ts1 = ts0 + 4 * TS_INC
        ts1_txt = ts_to_bq(ts1)
        (bqents, rec, count) = self._bq_hist("ptn", "--ptn_id", ptn_id,
                                                    "--begin", ts0_txt,
                                                    "--end", ts1_txt)
        bsents = self._bs_hist("ptn", ptn_id = ptn_id,
                                      tv_begin = (ts0, 0),
                                      tv_end = (ts1, 0))
        self._bq_bs_hist_cmp(bqents, bsents)

    def test_033_bq_comp_hist_begin_end(self):
        """bq -p STORE --hist --comp --ptn_id 256 --end T0"""
        ptn_id = 256
        ts0 = TS_BEGIN + 4 * TS_INC
        ts0_txt = ts_to_bq(ts0)
        ts1 = ts0 + 4 * TS_INC
        ts1_txt = ts_to_bq(ts1)
        (bqents, rec, count) = self._bq_hist("comp", "--ptn_id", ptn_id,
                                                     "--begin", ts0_txt,
                                                     "--end", ts1_txt)
        bsents = self._bs_hist("comp", ptn_id = ptn_id,
                                       tv_begin = (ts0, 0),
                                       tv_end = (ts1, 0))
        self._bq_bs_hist_cmp(bqents, bsents)


if __name__ == "__main__":
    pystartup = os.getenv("PYTHONSTARTUP")
    if pystartup:
        execfile(pystartup)
    LOGFMT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
    DATEFMT = "%F %T"
    logging.basicConfig(format=LOGFMT, datefmt=DATEFMT)
    log.setLevel(logging.INFO)
    unittest.TestLoader.testMethodPrefix = "test_"
    MAKE_STORE = True
    unittest.main(verbosity = 2, failfast = True)
