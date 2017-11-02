#!/usr/bin/env python
import os
import sys
import shutil
from baler import named2darray as n2da

TS0 = 1509667200
D = 3600
MN = 60
HR = 60*MN
DY = 24*HR

data = {
    "n2da/sparse_wide.n2da": [
        (TS0, 256, 100),
        (TS0, 257, 100),
        (TS0, 65534, 200),
        (TS0, 65535, 200),
        (TS0 + 30*DY, 256, 300),
        (TS0 + 30*DY, 257, 300),
        (TS0 + 30*DY, 65534, 400),
        (TS0 + 30*DY, 65535, 400),
    ],
    "n2da/sparse_exp.n2da": [
        (TS0, 256, 1),
        (TS0, 257, 1),
        (TS0, 65534, 10),
        (TS0, 65535, 10),
        (TS0 + 30*DY, 256, 100),
        (TS0 + 30*DY, 257, 100),
        (TS0 + 30*DY, 65534, 1000),
        (TS0 + 30*DY, 65535, 1000),
    ]
}

shutil.rmtree("n2da/", True)
os.mkdir("n2da/")

for (path, vdata) in data.iteritems():
    n2 = n2da.Named2DArray(path, "w")
    for p in vdata:
        n2.append(*p)
