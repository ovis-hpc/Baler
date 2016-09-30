#!/usr/bin/python

import os
import sys
import testenv
import re
import subprocess as sp

from baler import Bq

benv = testenv.get_benv()

bs = Bq.Bstore()
bs.open(benv['BSTORE'])
pitr = Bq.Bptn_iter(bs)
ptns = set(str(p) for p in pitr)

# gen-ptns.pl generates with \u2022 wildcard.
proc = sp.Popen("./gen-ptns.pl", stdout=sp.PIPE, shell=True)
r = re.compile(u"\u2022")
for p in proc.stdout:
    p = p.strip().decode('utf-8')
    p = r.sub("<dec>", p)
    p = "<host> " + str(p)
    ptns.remove(p)

assert(len(ptns) == 0)
