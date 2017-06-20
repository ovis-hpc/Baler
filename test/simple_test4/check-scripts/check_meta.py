#!/usr/bin/env python
import testenv
from baler import Bq

benv = testenv.get_benv()

bs = Bq.Bstore()
bs.open(benv['BSTORE'])

ptn_count = 0
meta = bs.meta_cluster()
for bmc in meta:
    print "----------"
    print "bmc:", bmc.meta_ptn()
    for x in bmc:
        ptn_count += 1
        print "\tptn:", x
assert(int(benv['BTEST_N_PATTERNS']) == ptn_count)
