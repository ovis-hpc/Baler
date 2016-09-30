#!/usr/bin/python

import testenv

benv = testenv.get_benv()

for (k,v) in benv.iteritems():
    print k, ":", v
