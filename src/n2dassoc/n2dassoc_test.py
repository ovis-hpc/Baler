#!/usr/bin/env python

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

import os
import sys
import shutil
import unittest
import re
import subprocess as sp
from baler import named2darray as n2da

TEST_DIR = "./testdir"
TMP_DIR = TEST_DIR + "/tmpdir"
INPUT_DIR = TEST_DIR + "/input"
TARGET_DIR = TEST_DIR + "/target"
N_INPUT = 16 # multiples of 4
N_TARGET = N_INPUT/4
MAX_Y = 128
MID_RANGE = range(MAX_Y/4, MAX_Y*3/4)
TARGET_LIST = TEST_DIR + "/tgt.list"
LHS_LIST = TEST_DIR + "/lhs.list"
RULE_FILE = TEST_DIR + "/rule.txt"
N2DASSOC_LOG = TEST_DIR + "/n2dassoc.log"

CFG_TXT = """
tmpdir = %(tmpdir)s
confidence = 0.75
significance = 0.25
difference = 0.10
rulefile = %(rulefile)s
targetfile = %(targetfile)s
lhsfile = %(lhsfile)s
threads = 4
maxdepth = 128
""" % {
    "tmpdir": TMP_DIR,
    "rulefile": RULE_FILE,
    "targetfile": TARGET_LIST,
    "lhsfile": LHS_LIST,
}
CFG_FILE = TEST_DIR + "/n2dassoc.cfg"

def lhs_name(_id):
    return "input%03d" % _id

def lhs_path(_id):
    return INPUT_DIR + "/" + lhs_name(_id) + ".n2da"

def tgt_name(_id):
    return "target%03d" % _id

def tgt_path(_id):
    return TARGET_DIR + "/" + tgt_name(_id) + ".n2da"

def gen_lhs(_id):
    name = lhs_name(_id)
    path = lhs_path(_id)
    n2 = n2da.Named2DArray(path, "w")
    n2.set_name(name)
    n2.set_x_bin_width(1)
    n2.set_y_bin_width(1)
    cat = _id % 4
    off_x = MAX_Y * (_id / 4)
    for x in range(0, MAX_Y):
        for y in range(0, MAX_Y):
            qx = 0 if x < MAX_Y/2 else 1
            qy = 0 if y < MAX_Y/2 else 1
            q = (qy << 1) | qx
            if cat == q and (x not in MID_RANGE or y not in MID_RANGE):
                continue # the L-shape hole
            n2.append(off_x + x, y, 100)


def gen_target(_id):
    # input(4x, 4x+1, 4x+2, 4x+3) ==> target(x)
    name = tgt_name(_id)
    path = tgt_path(_id)
    n2 = n2da.Named2DArray(path, "w")
    n2.set_name(name)
    n2.set_x_bin_width(1)
    n2.set_y_bin_width(1)
    off_x = MAX_Y * _id
    for x in MID_RANGE:
        for y in MID_RANGE:
            n2.append(off_x + x, y, 100)


class N2DAssocTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Prepare input
        shutil.rmtree(TEST_DIR, ignore_errors=True)
        os.makedirs(TMP_DIR);
        os.makedirs(INPUT_DIR)
        os.makedirs(TARGET_DIR)
        # LHS generation
        f = open(LHS_LIST, "w")
        for i in range(0, N_INPUT):
            f.write(lhs_path(i) + "\n")
            gen_lhs(i)
        f.close()
        # Target generation
        f = open(TARGET_LIST, "w")
        for i in range(0, N_TARGET):
            f.write(tgt_path(i) + "\n")
            gen_target(i)
        f.close()
        # cfg generation
        f = open(CFG_FILE, "w")
        f.write(CFG_TXT)
        f.close()

    @classmethod
    def tearDownClass(cls):
        pass

    def testN2DAssoc(self):
        GDB_SERVER = 0 # NOTE set this to 1 to enable gdb debugging
        GDB = "gdbserver localhost:12345"
        cmd = "%(gdb)s n2dassoc -c %(cfg)s > %(log)s" % {
            "gdb": GDB if GDB_SERVER else "",
            "cfg": CFG_FILE,
            "log": N2DASSOC_LOG,
        }
        proc = sp.Popen(cmd, shell=True)
        rc = proc.wait()
        self.assertEqual(rc, 0)
        r_set = set()
        # Now, check the correctness
        for r_no in range(0, N_TARGET):
            e = "{input%03d,input%03d,input%03d,input%03d}=>{target%03d}" % \
                (4*r_no, 4*r_no+1, 4*r_no+2, 4*r_no+3, r_no)
            r_set.add(e)
        f = open(RULE_FILE)
        for l in f:
            l = l.strip()
            r_set.remove(l)
        self.assertEqual(len(r_set), 0)
        f.close()


if __name__ == "__main__":
    unittest.main()
