#!/usr/bin/python

import time
from StringIO import StringIO
from baler import Bq

def sign(num):
    if num < 0:
        return -1
    return 1

def fmt_ts(tv_sec, tv_usec):
    tm = time.localtime(tv_sec)
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
	    tv_usec,
	    tz_hr,
	    tz_min
    )
    return s


def fmt_msg(msg):
    sio = StringIO()
    sio.write(fmt_ts(msg.tv_sec(), msg.tv_usec()))
    sio.write(" ")
    for tkn in msg:
        sio.write(tkn.tkn_str())
    return sio.getvalue()
