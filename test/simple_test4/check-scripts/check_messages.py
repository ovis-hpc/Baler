#!/usr/bin/python

import os
import sys
import testenv
import re
import subprocess as sp
import util

from baler import Bq

class Messages(object):
    def __init__(self, bs):
        self.mitr = Bq.Bmsg_iter(bs)

    def __iter__(self):
        for m in self.mitr:
            yield util.fmt_msg(m)


def consume_msg(itr, listA, listB):
    ts0 = listA[0].split(' ')[0]
    while True :
        try :
            m = next(itr)
        except StopIteration, e :
            break
        m = m.strip()
        ts1 = m.split(' ')[0]
        if ts0 != ts1:
            listB.append(m)
            break
        listA.append(m)

benv = testenv.get_benv()

bs = Bq.Bstore()
bs.open(benv['BSTORE'])

itr0 = iter(Messages(bs))
proc = sp.Popen("./gen-log.pl", stdout=sp.PIPE, stderr=sp.PIPE, shell=True)
itr1 = iter(proc.stdout)

list00 = []
list01 = []
list10 = []
list11 = []

msg0 = next(itr0)
msg1 = next(itr1)

list01.append(msg0.strip())
list11.append(msg1.strip())

while True :
    if not list01 or not list11:
        break
    list00 = list01
    list01 = []
    list10 = list11
    list11 = []
    consume_msg(itr0, list00, list01)
    consume_msg(itr1, list10, list11)
    set0 = set(list00)
    set1 = set(list10)
    assert(set0 == set1)

assert(not list01)
assert(not list11)
