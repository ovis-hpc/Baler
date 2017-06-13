#!/usr/bin/python

from .. import util
from .. import Bq

def eng_count(ptn):
    count = 0
    for tkn in ptn:
        if tkn.has_type(Bq.BTKN_TYPE_WORD):
            count += 1
    return count

def eng_cmp(a, b):
    a_len = a.tkn_count()
    b_len = b.tkn_count()
    a_eng = eng_count(a)
    b_eng = eng_count(b)
    ar = float(a_eng) / a_len
    br = float(b_eng) / b_len
    if ar < br:
        return -1
    if ar > br:
        return 1
    return 0

class PtnCmp_ENG_RATIO_ASC(util.PtnCmp):
    def __call__(self, a, b):
        return eng_cmp(a, b)

class PtnCmp_ENG_RATIO_DESC(util.PtnCmp):
    def __call__(self, a, b):
        return eng_cmp(b, a)

class PtnCmp_ENG_RATIO(util.PtnCmp):
    def __call__(self, a, b):
        return eng_cmp(b, a)
