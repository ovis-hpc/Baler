# Copyright (c) 2017 Open Grid Computing, Inc. All rights reserved.
# Copyright (c) 2017 Sandia Corporation. All rights reserved.
#
# Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
# license for use of this work by or on behalf of the U.S. Government.
# Export of this program may require a license from the United States
# Government.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the BSD-type
# license below:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#      Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#
#      Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials provided
#      with the distribution.
#
#      Neither the name of Sandia nor the names of any contributors may
#      be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
#      Neither the name of Open Grid Computing nor the names of any
#      contributors may be used to endorse or promote products derived
#      from this software without specific prior written permission.
#
#      Modified source versions must be plainly marked as such, and
#      must not be misrepresented as being the original software.
#
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import logging
import collections
import copy
import StringIO
import time
import calendar
import re
import json
import Bq
import curses
import pkgutil
from datetime import datetime
from dateutil import tz


logger = logging.getLogger(__name__)

TZ_LOCAL = tz.tzlocal()

class _DEBUG_(object): pass

DEBUG = _DEBUG_() # Debug object

def sign(num):
    if num < 0:
        return -1
    return 1

class Timestamp(collections.namedtuple("Timestamp", ["sec", "usec"])):
    TS_REGEX = re.compile("(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)(?:\.(\d{6}))?(?:([+-]\d\d):(\d\d))?")
    @staticmethod
    def fromJSONObj(jobj):
        return Timestamp(long(jobj["sec"]), int(jobj["usec"]))

    @staticmethod
    def fromStr(s):
        m = Timestamp.TS_REGEX.match(s)
        if not m:
            raise ValueError("Invalid format")
        (y,m,d,H,M,S,u,zh,zm) = (int(x) if x!=None else None for x in m.groups())
        if zh == None:
            # Unknown target timezone, treat as local time
            ts_sec = time.mktime((y,m,d,H,M,S,0,0,-1))
        else:
            ts_sec = calendar.timegm((y,m,d,H,M,S))
            zh = int(zh)
            zm = sign(zh)*int(zm)
            ts_sec -= zh*3600 + zm*60
        if u:
            ts_usec = int(u)
        else:
            ts_usec = 0
        return Timestamp(ts_sec, ts_usec)

    def my_fmt(self):
        tm = time.localtime(self.sec)
        if tm.tm_isdst:
            tzsec = time.altzone
        else:
            tzsec = time.timezone
        # NOTE: Apparently time.timezone is #sec to UTC, i.e. CST is 21600
        tz_hr = -sign(tzsec)*abs(tzsec)/3600
        tz_min = (abs(tzsec) % 3600)/60
        s = "%d-%02d-%02dT%02d:%02d:%02d.%06d%+03d:%02d" % (
                tm.tm_year,
                tm.tm_mon,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec,
                self.usec,
                tz_hr,
                tz_min
        )
        return s

    def dt_fmt(self):
        global TZ_LOCAL
        dt = datetime.fromtimestamp(self.sec, tz=TZ_LOCAL)
        return dt.isoformat()

    def __str__(self):
        return self.my_fmt()


class IDSet(set):
    def __init__(self, obj=None):
        super(IDSet, self).__init__()
        if obj != None:
            self.add_smart(obj)

    def add_number(self, num):
        self.add(num)

    def add_numbers(self, iterable):
        for x in iterable:
            self.add(x)

    def add_csv(self, csv=str()):
        for s in csv.split(','):
            t = s.split("-")
            x0 = int(t[0])
            x1 = x0
            if len(t) > 1:
                x1 = int(t[1])
            for i in xrange(x0, x1+1):
                self.add(i)

    def add_smart(self, obj):
        if type(obj) == str:
            return self.add_csv(obj)
        try:
            # first, try iterable
            for x in obj:
                self.add_smart(x)
        except TypeError:
            # if failed, try single number
            self.add_number(obj)

    def to_csv(self):
        s = [x for x in iter(self)]
        s.sort()
        prev = None
        sio = StringIO.StringIO()
        rflag = False
        for x in s:
            if prev == None:
                # this is the first item
                sio.write(str(x))
                prev = x
                continue
            if x - prev > 1:
                if rflag:
                    sio.write("-%d" % prev)
                    rflag = False
                sio.write(",%d" % x)
            else:
                rflag = True
            prev = x
        if rflag:
            sio.write("-%d" % prev)
            rflag = False
        ret = sio.getvalue()
        sio.close()
        return ret


class IterFilter(object):
    def __init__(self, itr, **kwargs):
        self.itr = itr

    def obj(self):
        return self.itr.obj()

    def first(self):
        return self.itr.first()

    def last(self):
        return self.itr.last()

    def next(self):
        return self.itr.next()

    def prev(self):
        return self.itr.prev()


class MsgIterFilter(IterFilter):
    def __init__(self, itr):
        super(MsgIterFilter, self).__init__(itr)

class ListIter(object):
    def __init__(self, lst):
        self.lst = lst
        self.idx = 0

    def _valid(self):
        return 0 <= self.idx and self.idx < len(self.lst)

    def __iter__(self):
        while self._valid():
            yield self.lst[self.idx]
            self.idx += 1

    def obj(self):
        if self._valid():
            return self.lst[self.idx]
        return None

    def get_pos(self):
        return self.idx

    def set_pos(self, pos):
        assert(type(pos) == int)
        self.idx = pos

    def first(self):
        self.idx = 0
        return self.obj()

    def next(self):
        self.idx += 1
        return self.obj()

    def prev(self):
        self.idx += 1
        return self.obj()

    def last(self):
        self.idx = len(self.lst) - 1
        return self.obj()

_ATABLE = {
    0: None,
    1: curses.A_BOLD,
    4: curses.A_UNDERLINE,
    30: None,
    31: 0x100,
    32: 0x200,
    33: 0x300,
    34: 0x400,
    35: 0x500,
    36: 0x600,
    37: 0x700,
}
_AREX = re.compile("(\\d+)(?:m|;)")
DEBUG.cpair = []
def ansi_to_curses(_str):
    DEBUG._str = _str
    ret = None
    for m in _AREX.finditer(_str):
        (num,) = m.groups()
        try:
            x = _ATABLE[int(num)]
            if x == None: # reset
                ret = None
                continue
            if ret == None:
                ret = x
                continue
            c = x & 0x700
            a = x & ~0x700
            if c:
                # replace color
                ret = (ret & ~0x700) | c
            if a:
                # set attribute
                ret |= a
        except KeyError:
            pass # do nothing for the non-supported code
    DEBUG.cpair.append((_str, ret))
    return ret


_CREX = re.compile("(\033\\[[^m]+m)|([^\033]*)")
def curses_addnstr(win, r, c, _str, n, offset=0):
    """ Parse ANSI-color escaped `_str` string and print it on `win` """
    column = 0
    attr = None
    DEBUG._str = _str
    DEBUG.r = r
    DEBUG.c = c
    DEBUG.n = n
    DEBUG.matches = []
    DEBUG.pair = []
    for m in _CREX.finditer(_str):
        (esc, text) = m.groups()
        DEBUG.matches.append((esc, text))
        if n <= 0:
            break # cannot print anymore
        if esc:
            # This is an escape sequence, change color accordingly
            attr = ansi_to_curses(esc)
        if text != None:
            # add text
            l = len(text)
            if offset:
                offset -= l
            if offset > 0:
                continue
            if offset < 0:
                text = text[offset:]
                l = len(text)
            DEBUG.pair.append((attr, text))
            if attr == None:
                win.addnstr(r, c, text, n)
            else:
                win.addnstr(r, c, text, n, attr)
            n -= l
            c += l

class PtnCmp(object):
    def __call__(self, a, b):
        raise NotImplementedError()

def method_cmp(ma, mb):
    # ma and mb are both bound methods
    va = ma()
    vb = mb()
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0

class PtnCmp_PTN_ID(PtnCmp):
    def __call__(self, a, b):
        # a and b are both Bq.bptn
        return method_cmp(a.ptn_id, b.ptn_id)

class PtnCmp_PTN_ID_ASC(PtnCmp):
    def __call__(self, a, b):
        # a and b are both Bq.bptn
        return method_cmp(a.ptn_id, b.ptn_id)

class PtnCmp_PTN_ID_DESC(PtnCmp):
    def __call__(self, a, b):
        # a and b are both Bq.bptn
        return method_cmp(b.ptn_id, a.ptn_id)

class PtnCmp_FIRST_SEEN_ASC(PtnCmp):
    def __call__(self, a, b):
        # a and b are both Bq.bptn
        return method_cmp(a.first_seen, b.first_seen)

class PtnCmp_FIRST_SEEN_DESC(PtnCmp):
    def __call__(self, a, b):
        # a and b are both Bq.bptn
        return method_cmp(b.first_seen, a.first_seen)

class PtnCmp_LAST_SEEN_ASC(PtnCmp):
    def __call__(self, a, b):
        # a and b are both Bq.bptn
        return method_cmp(a.last_seen, b.last_seen)

class PtnCmp_LAST_SEEN_DESC(PtnCmp):
    def __call__(self, a, b):
        # a and b are both Bq.bptn
        return method_cmp(b.last_seen, a.last_seen)

class PtnCmp_TKN_COUNT_ASC(PtnCmp):
    def __call__(self, a, b):
        # a and b are both Bq.bptn
        return method_cmp(a.tkn_count, b.tkn_count)

class PtnCmp_TKN_COUNT_DESC(PtnCmp):
    def __call__(self, a, b):
        # a and b are both Bq.bptn
        return method_cmp(b.tkn_count, a.tkn_count)

class PtnCmp_MSG_COUNT_ASC(PtnCmp):
    def __call__(self, a, b):
        # a and b are both Bq.bptn
        return method_cmp(a.msg_count, b.msg_count)

class PtnCmp_MSG_COUNT_DESC(PtnCmp):
    def __call__(self, a, b):
        # a and b are both Bq.bptn
        return method_cmp(b.msg_count, a.msg_count)

def get_ptn_cmp_by_name(name):
    # try built-in PtnCmp first
    cls_name = "PtnCmp_" + name.upper()
    cls = None
    try:
        cls = globals()[cls_name]
    except:
        # not found, search the comparator from the package
        import baler.ptn_cmp_ext as pce
        for imp, mname, ispkg in pkgutil.iter_modules(pce.__path__):
            if ispkg:
                continue
            mod = __import__(pce.__name__ + "." + mname, fromlist = "X")
            try:
                cls = getattr(mod, cls_name)
            except:
                # not found, do nothing
                continue
            # found!
            break
    if cls and issubclass(cls, PtnCmp):
        return cls() # return comparator instance
    return None

def sort_ptns(ptns, cmp_name):
    _cmp = get_ptn_cmp_by_name(cmp_name)
    ptns.sort(_cmp)
    return ptns
