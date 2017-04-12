#!/usr/bin/env python
import logging
import Bq
logger = logging.getLogger(__name__)

# a collection of comparator
COMP = {}

def register_ptn_cmp(name, _cmp):
    """Register a comparator to the comparator collection.

    Registering an existing `name` will overwrite the previously registered
    comparator.

    `_cmp` is a function (x,y) returning:
        -1 if x is before y,
        1  if x is after y, and
        0  if x and y are of the same order.
    """
    COMP[name] = _cmp


def get_ptn_cmp(name):
    return COMP[name]



#################################
####### basic comparators #######
#################################

def __ptn_attr_asc(attr, x, y):
    _x = getattr(x, attr)()
    _y = getattr(y, attr)()
    if _x < _y:
        return -1
    if _x > _y:
        return 1
    return 0


def __ptn_cmp_msg_count_asc(x,y):
    return __ptn_attr_asc("msg_count", x, y)
register_ptn_cmp("msg_count_asc", __ptn_cmp_msg_count_asc)

def __ptn_cmp_msg_count_desc(x,y):
    return __ptn_attr_asc("msg_count", y, x)
register_ptn_cmp("msg_count_desc", __ptn_cmp_msg_count_desc)


def __ptn_cmp_ptn_id_asc(x,y):
    return __ptn_attr_asc("ptn_id", x, y)
register_ptn_cmp("ptn_id_asc", __ptn_cmp_ptn_id_asc)

def __ptn_cmp_ptn_id_desc(x,y):
    return __ptn_attr_asc("ptn_id", y, x)
register_ptn_cmp("ptn_id_desc", __ptn_cmp_ptn_id_desc)


def __ptn_cmp_first_seen_asc(x,y):
    return __ptn_attr_asc("first_seen", x, y)
register_ptn_cmp("first_seen_asc", __ptn_cmp_first_seen_asc)

def __ptn_cmp_first_seen_desc(x,y):
    return __ptn_attr_asc("first_seen", y, x)
register_ptn_cmp("first_seen_desc", __ptn_cmp_first_seen_desc)


def __ptn_cmp_last_seen_asc(x,y):
    return __ptn_attr_asc("last_seen", x, y)
register_ptn_cmp("last_seen_asc", __ptn_cmp_last_seen_asc)

def __ptn_cmp_last_seen_desc(x,y):
    return __ptn_attr_asc("last_seen", y, x)
register_ptn_cmp("last_seen_desc", __ptn_cmp_last_seen_desc)


#############################################
####### English word ratio comparator #######
#############################################

def __ptn_eng_ratio(ptn):
    count = 0
    for tkn in ptn:
        count += tkn.has_type(Bq.BTKN_TYPE_WORD)
    return float(count)/ptn.tkn_count()

def __ptn_cmp_eng_asc(x,y):
    _x = __ptn_eng_ratio(x)
    _y = __ptn_eng_ratio(y)
    if _x < _y:
        return -1
    if _x > _y:
        return 1
    return 0
register_ptn_cmp("eng_asc", __ptn_cmp_eng_asc)

def __ptn_cmp_eng_desc(x,y):
    return __ptn_cmp_eng_asc(y,x)
register_ptn_cmp("eng_desc", __ptn_cmp_eng_desc)
