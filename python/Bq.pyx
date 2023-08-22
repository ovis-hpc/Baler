from __future__ import print_function
import cython
from cpython cimport PyObject, Py_INCREF
import datetime as dt
from libc.stdint cimport *
from libc.stdlib cimport *
from libc.errno cimport *
# from sosdb import Array
import os
cimport Bs

cdef uint64_t btkn_type_mask_from_str(const char *_str):
    return Bs.btkn_type_mask_from_str(_str)

BTKN_TYPE_TYPE = Bs.BTKN_TYPE_TYPE
BTKN_TYPE_PRIORITY = Bs.BTKN_TYPE_PRIORITY
BTKN_TYPE_VERSION = Bs.BTKN_TYPE_VERSION
BTKN_TYPE_TIMESTAMP = Bs.BTKN_TYPE_TIMESTAMP
BTKN_TYPE_HOSTNAME = Bs.BTKN_TYPE_HOSTNAME
BTKN_TYPE_SERVICE = Bs.BTKN_TYPE_SERVICE
BTKN_TYPE_PID = Bs.BTKN_TYPE_PID
BTKN_TYPE_IP4_ADDR = Bs.BTKN_TYPE_IP4_ADDR
BTKN_TYPE_IP6_ADDR = Bs.BTKN_TYPE_IP6_ADDR
BTKN_TYPE_ETH_ADDR = Bs.BTKN_TYPE_ETH_ADDR
BTKN_TYPE_HEX_INT = Bs.BTKN_TYPE_HEX_INT
BTKN_TYPE_DEC_INT = Bs.BTKN_TYPE_DEC_INT
BTKN_TYPE_SEPARATOR = Bs.BTKN_TYPE_SEPARATOR
BTKN_TYPE_FLOAT = Bs.BTKN_TYPE_FLOAT
BTKN_TYPE_PATH = Bs.BTKN_TYPE_PATH
BTKN_TYPE_URL = Bs.BTKN_TYPE_URL
BTKN_TYPE_WORD = Bs.BTKN_TYPE_WORD
BTKN_TYPE_TEXT = Bs.BTKN_TYPE_TEXT
BTKN_TYPE_WHITESPACE = Bs.BTKN_TYPE_WHITESPACE

tkn_type_strs = {
    Bs.BTKN_TYPE_TYPE : "<type>",
    Bs.BTKN_TYPE_PRIORITY : "<prio>",
    Bs.BTKN_TYPE_VERSION : "<vers>",
    Bs.BTKN_TYPE_TIMESTAMP : "<ts>",
    Bs.BTKN_TYPE_HOSTNAME : "<host>",
    Bs.BTKN_TYPE_SERVICE : "<svc>",
    Bs.BTKN_TYPE_PID : "<pid>",
    Bs.BTKN_TYPE_IP4_ADDR : "<ip4>",
    Bs.BTKN_TYPE_IP6_ADDR : "<ip6>",
    Bs.BTKN_TYPE_ETH_ADDR : "<mac>",
    Bs.BTKN_TYPE_HEX_INT : "<hex>",
    Bs.BTKN_TYPE_DEC_INT : "<dec>",
    Bs.BTKN_TYPE_SEPARATOR : "<sep>",
    Bs.BTKN_TYPE_FLOAT : "<float>",
    Bs.BTKN_TYPE_PATH : "<path>",
    Bs.BTKN_TYPE_URL : "<url>",
    Bs.BTKN_TYPE_WORD : "<word>",
    Bs.BTKN_TYPE_TEXT : "*",
    Bs.BTKN_TYPE_WHITESPACE : " "
}

cdef class Bstore:

    cdef Bs.bstore_t c_store
    cdef iters
    cdef plugin
    cdef path

    def __cinit__(self, plugin='bstore_sos'):
        self.c_store = NULL
        self.plugin = plugin

    def open(self, path, int flags=Bs.O_RDWR, int mode=0660):
        self.iters = []
        self.path = path
        self.c_store = Bs.bstore_open(self.plugin.encode(), self.path.encode(), flags, mode)
        if self.c_store is NULL:
            raise ValueError("Error {0} opening the baler database at '{1}'."
                             .format(errno, self.path))
        return self

    def close(self):
        if self.iters:
            for iter in self.iters:
                iter.__close_store()
                del iter
        self.iters = None
        if self.c_store is not NULL:
            Bs.bstore_close(self.c_store)
            self.c_store = NULL

    def __dealloc__(self):
        # automatically close at deallocation, just in case that the application
        # has not already closed the store.
        self.close()

    def tkn_by_id(self, tkn_id):
        cdef Bs.btkn_id_t id_ = <Bs.btkn_id_t>tkn_id
        cdef Bs.btkn_t btkn
        cdef Btkn tkn
        btkn = Bs.bstore_tkn_find_by_id(self.c_store, id_)
        if btkn != NULL:
            tkn = Btkn()
            tkn.c_tkn = btkn
            return tkn
        return None

    def tkn_by_name(self, tkn_name):
        cdef Bs.btkn_t btkn
        cdef Btkn tkn
        btkn = Bs.bstore_tkn_find_by_name(self.c_store, tkn_name.encode(), len(tkn_name))
        if btkn != NULL:
            tkn = Btkn()
            tkn.c_tkn = btkn
            return tkn
        return None

    def ptn_by_id(self, ptn_id):
        cdef Bs.bptn_id_t id_ = <Bs.bptn_id_t>ptn_id
        cdef Bs.bptn_t c_ptn
        cdef Bptn ptn
        c_ptn = Bs.bstore_ptn_find(self.c_store, id_)
        if c_ptn != NULL:
            ptn = Bptn()
            ptn.c_ptn = c_ptn
            ptn.store = self
            return ptn
        return None

    def tkn_type_str(self, typ_id):
        if typ_id >= Bs.BTKN_TYPE_LAST:
            raise ValueError("The type id {0} is not valid.".format(typ_id))
        if typ_id in tkn_type_strs:
            return tkn_type_strs[typ_id]
        tkn = self.tkn_by_id(typ_id)
        if not tkn:
            raise ValueError("The user-defined type id {0} was not found.".format(typ_id))
        typ_str = tkn.tkn_str()
        del tkn
        return typ_str

    cdef meta_cluster(self, float diff_ratio=0.30,
                             float refinement_speed=2.0,
                             float looseness=0.20):
        cdef list _list = list()
        cdef Bs.bmc_params_s params
        params.diff_ratio = diff_ratio
        params.refinement_speed = refinement_speed
        params.looseness = looseness
        cdef Bs.bmc_list_t bmc_list = Bs.bmc_list_compute(self.c_store, &params)
        cdef Bs.bmc_list_iter_t itr = Bs.bmc_list_iter_new(bmc_list)
        cdef Bs.bmc_t c_bmc
        c_bmc = Bs.bmc_list_iter_first(itr)
        while (c_bmc):
            pybmc = Bmc()
            pybmc.c_init(self, c_bmc)
            _list.append(pybmc)
            c_bmc = Bs.bmc_list_iter_next(itr)
        Bs.bmc_list_iter_free(itr)
        Bs.bmc_list_free(bmc_list)
        return _list

    cdef attr_new(self, const char *attr_type):
        cdef int rc
        rc = Bs.bstore_attr_new(self.c_store, attr_type)
        if rc == EEXIST:
            raise ValueError("attribute '%s' existed" % attr_type)
        if rc:
            raise RuntimeError("bstore_attr_new() return code: %d" % rc)

    cdef attr_find(self, const char *attr_type):
        cdef int rc
        rc = Bs.bstore_attr_find(self.c_store, attr_type)
        if rc:
            return False
        return True

    cdef ptn_attr_value_set(self, int ptn_id,
                                   const char *attr_type,
                                   const char *attr_value):
        cdef int rc
        rc = Bs.bstore_ptn_attr_value_set(self.c_store, ptn_id,
                                                     attr_type,
                                                     attr_value)
        if rc:
            raise RuntimeError("bstore_ptn_attr_value_set() rc: %d" % rc)

    cdef ptn_attr_get(self, int ptn_id, const char *attr_type):
        cdef char *attr_value
        attr_value = Bs.bstore_ptn_attr_get(self.c_store, ptn_id, attr_type)
        if not attr_value:
            if errno == ENOENT:
                raise KeyError("'%s' not found" % attr_type)
            raise RuntimeError("bstore_ptn_attr_get() errno: %d" % errno)
        return attr_value

    cdef ptn_attr_value_add(self, int ptn_id,
                                   const char *attr_type,
                                   const char *attr_value):
        cdef int rc
        rc = Bs.bstore_ptn_attr_value_add(self.c_store, ptn_id,
                                                        attr_type,
                                                        attr_value)
        if rc == EEXIST:
            raise ValueError("(%d, '%s', '%s') existed" %
                                            (ptn_id, attr_type, attr_value))
        if rc:
            raise RuntimeError("bstore_ptn_attr_value_add() rc: %d" % rc)

    cdef ptn_attr_value_rm(self, int ptn_id,
                                  const char *attr_type,
                                  const char *attr_value):
        cdef int rc
        rc = Bs.bstore_ptn_attr_value_rm(self.c_store, ptn_id,
                                                       attr_type,
                                                       attr_value)
        if rc == ENOENT:
            raise LookupError("(%d, '%s', '%s') not found" %
                                            (ptn_id, attr_type, attr_value))
        if rc:
            raise RuntimeError("bstore_ptn_attr_value_add() rc: %d" % rc)


cdef class Bmc:
    cdef Bs.bmc_id_t _meta_id
    cdef Bptn _meta_ptn
    cdef list _list

    def __cinit__(self):
        self._meta_id = 0
        self._meta_ptn = Bptn()
        self._list = list()
        # NOTE: According to Cython doc (extension_types), Python attributes
        #       of the extension types are deallocated by Cython after
        #       __dealloc__() method returns.

    cdef c_init(self, Bstore bs, Bs.bmc_t bmc):
        self._meta_id = bmc.meta_id
        self._meta_ptn.c_ptn = Bs.bptn_dup(bmc.meta_ptn)
        self._meta_ptn.store = bs
        cdef Bs.bmc_iter_t c_iter = Bs.bmc_iter_new(bmc)
        cdef Bs.bptn_t c_ptn
        cdef Bptn ptn
        # note, we did not own c_ptn from c_iter
        c_ptn = Bs.bmc_iter_first(c_iter)
        while c_ptn:
            ptn = Bptn()
            ptn.c_ptn = Bs.bptn_dup(c_ptn)
            ptn.store = bs
            self._list.append(ptn)
            c_ptn = Bs.bmc_iter_next(c_iter)
        Bs.bmc_iter_free(c_iter)

    cdef Bs.bmc_id_t meta_id(self):
        return self._meta_id

    cdef Bptn meta_ptn(self):
        return self._meta_ptn

    def __iter__(self):
        if self._list:
            for x in self._list:
                yield x

cdef class Btkn:
    cdef Bs.btkn_t c_tkn
    cdef Bs.btkn_type_t c_typ

    def __cinit__(self):
        self.c_tkn = NULL

    def __dealloc__(self):
        if self.c_tkn is not NULL:
            Bs.btkn_free(self.c_tkn)
            self.c_tkn = NULL

    def tkn_id(self):
        return self.c_tkn.tkn_id

    def tkn_count(self):
        return self.c_tkn.tkn_count

    def tkn_str(self):
        s = self.c_tkn.tkn_str.cstr
        return s.decode()

    def ptn_tkn_str(self):
        if self.c_tkn.tkn_id in tkn_type_strs:
            s = tkn_type_strs[self.c_tkn.tkn_id]
            return s
        s = self.c_tkn.tkn_str.cstr
        return s.decode()

    def has_type(self, Bs.btkn_type_t tkn_type):
        if Bs.btkn_has_type(self.c_tkn, tkn_type) != 0:
            return True
        return False

    def type_mask(self):
        return self.c_tkn.tkn_type_mask

    def first_type(self):
        return Bs.btkn_first_type(self.c_tkn)

    cdef Bs.btkn_t alloc(self):
        return Bs.btkn_alloc(self.c_tkn.tkn_id, self.c_tkn.tkn_type_mask,
                             self.c_tkn.tkn_str.cstr, self.c_tkn.tkn_str.blen)

    cdef Bs.btkn_t dup(self):
        return Bs.btkn_dup(self.c_tkn)

    def __iter__(self):
        self.c_typ = Bs.btkn_first_type(self.c_tkn)
        return self

    def __next__(self):
        while self.c_typ < Bs.BTKN_TYPE_LAST:
            if Bs.btkn_has_type(self.c_tkn, self.c_typ) != 0:
                typ = self.c_typ
                self.c_typ += 1
                return typ
            self.c_typ += 1
        raise StopIteration

cdef class Biter:

    cdef Bstore store
    cdef Bs.bstore_iter_t c_iter
    cdef object py_obj
    cdef int c_rc
    cdef Bs.bstore_iter_filter_s c_filter

    def __init__(self, Bstore store):
        cdef Bs.bstore_iter_t c_it
        self.store = store
        if self.store.c_store == NULL:
            raise ValueError("The specified store is not open")
        c_it = self.iterNew()
        if c_it is NULL:
            raise MemoryError()
        self.c_iter = c_it
        self.c_rc = -1
        store.iters.append(self)

    def __dealloc__(self):
        if self.store and self.c_iter is not NULL:
            self.iterDel()
            self.c_iter = NULL

    def __iter__(self):
        """ iterate from current object forward. """
        if self.c_rc == -1: # newly created iterator
            self.first()
        while self.c_rc == 0:
            obj = self.obj()
            assert(obj != None)
            yield obj
            self.next()

    def __close_store(self):
        self.store = None

    def set_filter(self, **kwargs):
        """Specify filter conditions for the objects returned by the iterator

        Keyword Parameters:
        tv_begin -- A tuple of (secs, usecs). Matching objects will have a
                    have a timestamp greater than or equal this value
        tv_end   -- A tuple of (secs, usecs). Matching objects will have a
                    timestamp less or equal this value.
        time_attr-- The attribute to use for the time index.
        ptn_id   -- An integer. A matching object will have a ptn_id equal
                    this value.
        comp_id  -- An integer. A matching object will have a comp_id equal
                    this value.
        tkn_pos  -- A string returned by the get_pos() method. Sets the
                    position of the iterator where it was when get_pos()
                    was called.
        bin_width-- The width of the histogram bins in seconds.
        """
        Bs.bzero(&self.c_filter, sizeof(self.c_filter))
        if 'tv_begin' in kwargs and kwargs['tv_begin']:
            (self.c_filter.tv_begin.tv_sec, self.c_filter.tv_begin.tv_usec) = \
                                                        kwargs['tv_begin']
        if 'tv_end' in kwargs and kwargs['tv_end']:
            (self.c_filter.tv_end.tv_sec, self.c_filter.tv_end.tv_usec) = \
                                                        kwargs['tv_end']
        if 'ptn_id' in kwargs:
            self.c_filter.ptn_id = kwargs['ptn_id']
        if 'comp_id' in kwargs:
            self.c_filter.comp_id = kwargs['comp_id']
        if 'tkn_id' in kwargs:
            self.c_filter.tkn_id = kwargs['tkn_id']
        if 'tkn_pos' in kwargs:
            self.c_filter.tkn_pos = kwargs['tkn_pos']
        if 'bin_width' in kwargs:
            self.c_filter.bin_width = kwargs['bin_width']
        if 'attr_type' in kwargs:
            self.c_filter.attr_type = kwargs['attr_type']
        if 'attr_value' in kwargs:
            self.c_filter.attr_value = kwargs['attr_value']
        self.iterFilterSet(&self.c_filter)

    cdef obj_update(self, void *ptr):
        pass

    cdef object obj_wrap(self, void *c_obj):
        raise NotImplementedError

    cdef unsigned long card(self):
        raise NotImplementedError

    def obj(self):
        c_obj = self.iterObj()
        if c_obj:
            return self.obj_wrap(c_obj)
        return None

    def first(self):
        self.c_rc = self.iterFirst()
        return self.c_rc == 0

    def next(self):
        self.c_rc = self.iterNext()
        return self.c_rc == 0

    def prev(self):
        self.c_rc = self.iterPrev()
        return self.c_rc == 0

    def last(self):
        self.c_rc = self.iterLast()
        return self.c_rc == 0

    def find_fwd(self, **kwargs):
        self.c_rc = self.iterFindFwd(**kwargs)
        return self.c_rc == 0

    def find_rev(self, **kwargs):
        self.c_rc = self.iterFindRev(**kwargs)
        return self.c_rc == 0

    def get_pos(self):
        """Return the current iterator position

        Returns a string that represents the current iterator
        position. This string can be passed to set_pos() in order to
        start an iterator at a previously saved position. This is
        useful for handling pagination for a web back-end.

        The get_pos() function must be called before the call to
        next() in order to return the iterator position associated
        with the object returned by next(). Since the Python:

            for x in y:
                # ...

        paradigm calls next() implicitly, calling get_pos() inside the
        for loop will return the _next_ position on the iterator, not
        the one associated with the current object. This may be
        desireable in the case where the goal is to restart the
        iterator _after_ the last object previously returned.
        """
        cdef const char *pos_str
        cdef Bs.bstore_iter_pos_t c_pos_h = Bs.bstore_iter_pos_get(self.c_iter)
        if not c_pos_h:
            return None
        pos_str = Bs.bstore_pos_to_str(c_pos_h)
        return pos_str

    def set_pos(self, pos):
        """Set the iterator position to \c pos"""
        cdef int rc
        cdef const char *pos_str = <const char *>pos
        cdef Bs.bstore_iter_pos_t c_pos_h = Bs.bstore_pos_from_str(pos_str)
        if not c_pos_h:
            raise ValueError("The input position string is invalid for this iterator.")
        rc = Bs.bstore_iter_pos_set(self.c_iter, c_pos_h)
        if rc != 0:
            raise StopIteration("return code: %d" % rc)
        return 0

    def put_pos(self, pos):
        """Releases any resources associated with pos"""
        cdef int rc
        cdef const char *pos_str = <const char *>pos
        cdef Bs.bstore_iter_pos_t c_pos_h = Bs.bstore_pos_from_str(pos_str)
        if not c_pos_h:
            raise ValueError("The input position string is invalid for this iterator.")
        Bs.bstore_iter_pos_free(self.c_iter, c_pos_h)

    def count(self):
        """ Count the entries remaining in the iterator """
        pos = self.get_pos() # to recover the position
        count = 0
        rc = True
        while rc:
            count += 1
            rc = self.next()
        # recover the position
        if pos:
            self.set_pos(pos)
        return count

    cdef Bs.bstore_iter_t iterNew(self):
        raise NotImplementedError

    cdef void iterDel(self):
        raise NotImplementedError

    cdef void *iterObj(self):
        raise NotImplementedError

    def iterFindFwd(self, **kwargs):
        raise NotImplementedError

    def iterFindRev(self, **kwargs):
        raise NotImplementedError

    cdef int iterFirst(self):
        raise NotImplementedError

    cdef int iterNext(self):
        raise NotImplementedError

    cdef int iterPrev(self):
        raise NotImplementedError

    cdef int iterLast(self):
        raise NotImplementedError

    cdef int iterFilterSet(self, Bs.bstore_iter_filter_t f):
        raise NotImplementedError


cdef class Btkn_iter(Biter):
    def __init__(self, Bstore store):
        Biter.__init__(self, store)

    cdef Bs.bstore_iter_t iterNew(self):
        return Bs.bstore_tkn_iter_new(self.store.c_store)

    cdef void iterDel(self):
        Bs.bstore_tkn_iter_free(self.c_iter)

    cdef object obj_wrap(self, void *c_obj):
        btkn = Btkn()
        btkn.c_tkn = <Bs.btkn_t>c_obj
        return btkn

    cdef void *iterObj(self):
        return Bs.bstore_tkn_iter_obj(self.c_iter)

    cdef unsigned long card(self):
        return Bs.bstore_tkn_iter_card(self.c_iter)

    cdef int iterFirst(self):
        return Bs.bstore_tkn_iter_first(self.c_iter)

    cdef int iterNext(self):
        return Bs.bstore_tkn_iter_next(self.c_iter)

    cdef int iterPrev(self):
        return Bs.bstore_tkn_iter_prev(self.c_iter)

    cdef int iterLast(self):
        return Bs.bstore_tkn_iter_last(self.c_iter)

cdef class Bptn:
    cdef Bstore store
    cdef Bs.bptn_t c_ptn
    cdef int c_arg
    def __cinit__(self):
        self.c_ptn = NULL
        self.c_arg = 0

    def __dealloc__(self):
        if self.c_ptn is not NULL:
            Bs.bptn_free(self.c_ptn)
            self.c_ptn = NULL

    def ptn_id(self):
        """Returns the unique Pattern Identifier"""
        return self.c_ptn.ptn_id

    def first_seen(self):
        """Returns the first time this pattern was seen"""
        return self.c_ptn.first_seen.tv_sec

    def first_seen2(self):
        """Returns the first time tuple (unix_ts,usec) this pattern was seen"""
        return (self.c_ptn.first_seen.tv_sec, self.c_ptn.first_seen.tv_usec)

    def last_seen(self):
        """Returns the last time this pattern was seen"""
        return self.c_ptn.last_seen.tv_sec

    def last_seen2(self):
        """Returns the last time tuple (unix_ts,usec) this pattern was seen"""
        return (self.c_ptn.last_seen.tv_sec, self.c_ptn.last_seen.tv_usec)

    def tkn_count(self):
        """Returns the number of token postions in the pattern"""
        return self.c_ptn.tkn_count

    def msg_count(self):
        """Returns the number of messages matching this pattern"""
        return self.c_ptn.count

    def find_tkn(self, size_t pos, Bs.btkn_id_t tkn_id):
        """Search the pattern history at the specified position for a token"""
        cdef Bs.btkn_t c_tkn
        c_tkn = Bs.bstore_ptn_tkn_find(self.store.c_store,
                                       self.c_ptn.ptn_id,
                                       pos,
                                       tkn_id)
        if c_tkn != NULL:
            tkn = Btkn()
            tkn.c_tkn = c_tkn
            return tkn

        return None

    def __iter__(self):
        return self

    def __next__(self):
        cdef Bs.btkn_id_t tkn_id
        if self.c_arg < self.c_ptn.tkn_count:
            tkn_id = self.c_ptn.str.u64str[self.c_arg]
            tkn_id = tkn_id >> 8
            tkn = self.store.tkn_by_id(tkn_id)
            self.c_arg += 1
            return tkn
        self.c_arg = 0
        raise StopIteration

    def __str__(self):
        cdef int arg
        cdef Bs.btkn_id_t tkn_id
        ptn_str = ""
        for arg in range(0, self.c_ptn.tkn_count):
            tkn_id = self.c_ptn.str.u64str[arg]
            tkn_id = tkn_id >> 8
            tkn = self.store.tkn_by_id(tkn_id)
            ptn_str += tkn.ptn_tkn_str()
        return ptn_str


cdef class Bptn_attr:
    cdef Bs.bptn_attr_t c_ptn_attr

    def __cinit__(self):
        self.c_ptn_attr = NULL

    def __dealloc__(self):
        Bs.bptn_attr_free(self.c_ptn_attr)

    def __iter__(self):
        yield self.c_ptn_attr.ptn_id
        yield self.c_ptn_attr.attr_type
        yield self.c_ptn_attr.attr_value

    def as_list(self):
        return list(iter(self))

    def as_tuple(self):
        return tuple(iter(self))

    def ptn_id(self):
        return self.c_ptn_attr.ptn_id

    def attr_type(self):
        return self.c_ptn_attr.attr_type

    def attr_value(self):
        return self.c_ptn_attr.attr_value


cdef class Bptn_iter(Biter):
    """Create an iterator for Patterns

    By default the time attribute is "last_seen". To filter by the
    last time a pattern was seen, use the time_attr postitional
    argument to set_filter() and set it to "first_seen"

    For example:
    pi.set_filter(time_attr="first_seen",
                  tv_begin=(begin_secs, 0),
                  tv_end=(end_secs, 0))
    """
    def __init__(self, Bstore store):
        Biter.__init__(self, store)

    cdef Bs.bstore_iter_t iterNew(self):
        return Bs.bstore_ptn_iter_new(self.store.c_store)

    cdef void iterDel(self):
        Bs.bstore_ptn_iter_free(self.c_iter)

    cdef unsigned long card(self):
        return Bs.bstore_ptn_iter_card(self.c_iter)

    cdef object obj_wrap(self, void *c_obj):
        bptn = Bptn()
        bptn.c_ptn = <Bs.bptn_t>c_obj
        bptn.store = self.store
        return bptn

    def iterFindFwd(self, **kwargs):
        if "ptn_id" not in kwargs:
            raise KeyError("'ptn_id' argument is required")
        ptn_id = <int>kwargs["ptn_id"]
        return Bs.bstore_ptn_iter_find_fwd(self.c_iter, ptn_id)

    def iterFindRev(self, **kwargs):
        if "ptn_id" not in kwargs:
            raise KeyError("'ptn_id' argument is required")
        ptn_id = <int>kwargs["ptn_id"]
        return Bs.bstore_ptn_iter_find_rev(self.c_iter, ptn_id)

    cdef void *iterObj(self):
        return Bs.bstore_ptn_iter_obj(self.c_iter)

    cdef int iterFirst(self):
        return Bs.bstore_ptn_iter_first(self.c_iter)

    cdef int iterNext(self):
        return Bs.bstore_ptn_iter_next(self.c_iter)

    cdef int iterPrev(self):
        return Bs.bstore_ptn_iter_prev(self.c_iter)

    cdef int iterLast(self):
        return Bs.bstore_ptn_iter_last(self.c_iter)

    cdef int iterFilterSet(self, Bs.bstore_iter_filter_t f):
        return Bs.bstore_ptn_iter_filter_set(self.c_iter, f)


cdef class Bptn_attr_iter(Biter):
    def __init__(self, Bstore store):
        Biter.__init__(self, store)

    cdef Bs.bstore_iter_t iterNew(self):
        return Bs.bstore_ptn_attr_iter_new(self.store.c_store)

    cdef void iterDel(self):
        Bs.bstore_ptn_attr_iter_free(self.c_iter)

    cdef unsigned long card(self):
        return -1

    cdef object obj_wrap(self, void *c_obj):
        ptn_attr = Bptn_attr()
        ptn_attr.c_ptn_attr = <Bs.bptn_attr_t>c_obj
        return ptn_attr

    def iterFindFwd(self, **kwargs):
        ptn_id = <int>kwargs["ptn_id"]
        attr_type = <char*>kwargs["attr_type"]
        attr_value = <char*>kwargs["attr_value"]
        return Bs.bstore_ptn_attr_iter_find_fwd(self.c_iter,
                                           ptn_id, attr_type, attr_value)

    def iterFindRev(self, **kwargs):
        ptn_id = <int>kwargs["ptn_id"]
        attr_type = <char*>kwargs["attr_type"]
        attr_value = <char*>kwargs["attr_value"]
        return Bs.bstore_ptn_attr_iter_find_rev(self.c_iter,
                                           ptn_id, attr_type, attr_value)

    cdef void *iterObj(self):
        return Bs.bstore_ptn_attr_iter_obj(self.c_iter)

    cdef int iterFirst(self):
        return Bs.bstore_ptn_attr_iter_first(self.c_iter)

    cdef int iterNext(self):
        return Bs.bstore_ptn_attr_iter_next(self.c_iter)

    cdef int iterPrev(self):
        return Bs.bstore_ptn_attr_iter_prev(self.c_iter)

    cdef int iterLast(self):
        return Bs.bstore_ptn_attr_iter_last(self.c_iter)

    cdef int iterFilterSet(self, Bs.bstore_iter_filter_t f):
        return Bs.bstore_ptn_attr_iter_filter_set(self.c_iter, f)


cdef class Bptn_tkn_iter(Biter):
    def __init__(self, Bstore store, ptn_id = 0, tkn_pos = 0):
        Biter.__init__(self, store)
        self.set_filter(ptn_id=ptn_id, tkn_pos=tkn_pos)

    cdef Bs.bstore_iter_t iterNew(self):
        return Bs.bstore_ptn_tkn_iter_new(self.store.c_store)

    cdef void iterDel(self):
        Bs.bstore_ptn_tkn_iter_free(self.c_iter)

    cdef unsigned long card(self):
        return Bs.bstore_ptn_tkn_iter_card(self.c_iter)

    cdef object obj_wrap(self, void *c_obj):
        btkn = Btkn()
        btkn.c_tkn = <Bs.btkn_t>c_obj
        return btkn

    cdef void *iterObj(self):
        return Bs.bstore_ptn_tkn_iter_obj(self.c_iter)

    cdef int iterFirst(self):
        return Bs.bstore_ptn_tkn_iter_first(self.c_iter)

    cdef int iterLast(self):
        return Bs.bstore_ptn_tkn_iter_last(self.c_iter)

    cdef int iterNext(self):
        return Bs.bstore_ptn_tkn_iter_next(self.c_iter)

    cdef int iterPrev(self):
        return Bs.bstore_ptn_tkn_iter_prev(self.c_iter)

    cdef int iterFilterSet(self, Bs.bstore_iter_filter_t f):
        return Bs.bstore_ptn_tkn_iter_filter_set(self.c_iter, f)


cdef class Bmsg:
    cdef Bstore store
    cdef Bs.bmsg_t c_msg
    cdef int c_arg
    def __cinit__(self):
        self.c_msg = NULL
        self.c_arg = 0

    def __dealloc__(self):
        if self.c_msg is not NULL:
            Bs.bmsg_free(self.c_msg)
            self.c_msg = NULL

    def tv_sec(self):
        if self.c_msg is NULL:
            raise ValueError
        return self.c_msg.timestamp.tv_sec

    def tv_usec(self):
        if self.c_msg is NULL:
            raise ValueError
        return self.c_msg.timestamp.tv_usec

    def ptn_id(self):
        if self.c_msg is NULL:
            raise ValueError
        return self.c_msg.ptn_id

    def comp_id(self):
        if self.c_msg is NULL:
            raise ValueError
        return self.c_msg.comp_id

    def tkn_count(self):
        if self.c_msg is NULL:
            raise ValueError
        return self.c_msg.argc

    def __iter__(self):
        self.c_arg = 0
        return self

    def __next__(self):
        cdef Bs.btkn_id_t tkn_id
        if self.c_arg < self.c_msg.argc:
            tkn_id = self.c_msg.argv[self.c_arg]
            tkn_id = tkn_id >> 8
            tkn = self.store.tkn_by_id(tkn_id)
            self.c_arg += 1
            return tkn
        raise StopIteration

cdef class Bmsg_iter(Biter):
    def __init__(self, Bstore store):
        Biter.__init__(self, store)

    cdef Bs.bstore_iter_t iterNew(self):
        return Bs.bstore_msg_iter_new(self.store.c_store)

    cdef void iterDel(self):
        Bs.bstore_msg_iter_free(self.c_iter)

    cdef unsigned long card(self):
        return Bs.bstore_msg_iter_card(self.c_iter)

    cdef object obj_wrap(self, void *c_obj):
        bmsg = Bmsg()
        bmsg.c_msg = <Bs.bmsg_t>c_obj
        bmsg.store = self.store
        return bmsg

    cdef void *iterObj(self):
        return Bs.bstore_msg_iter_obj(self.c_iter)

    cdef int iterFirst(self):
        return Bs.bstore_msg_iter_first(self.c_iter)

    cdef int iterLast(self):
        return Bs.bstore_msg_iter_last(self.c_iter)

    cdef int iterNext(self):
        return Bs.bstore_msg_iter_next(self.c_iter)

    cdef int iterPrev(self):
        return Bs.bstore_msg_iter_prev(self.c_iter)

    cdef int iterFilterSet(self, Bs.bstore_iter_filter_t f):
        return Bs.bstore_msg_iter_filter_set(self.c_iter, f)

    def _iterFind(self, fwd, **kwargs):
        cdef Bs.timeval tval
        cdef Bs.timeval *tv
        try:
            kw_tv = kwargs["tv"]
            tval.tv_sec = kw_tv[0]
            tval.tv_usec = kw_tv[1]
            tv = &tval
        except:
            tv = NULL
        try:
            comp_id = kwargs["comp_id"]
        except:
            comp_id = 0
        try:
            ptn_id = kwargs["ptn_id"]
        except:
            ptn_id = 0
        if fwd:
            return Bs.bstore_msg_iter_find_fwd(self.c_iter, tv, comp_id, ptn_id)
        else:
            return Bs.bstore_msg_iter_find_rev(self.c_iter, tv, comp_id, ptn_id)

    def iterFindFwd(self, **kwargs):
        """Find the message in a forward direction

        Postion the iterator at the message matching the given key (tv, comp_id,
        ptn_id). If such key is not found, position the iterator at the next
        nearest message (forward direction).

        Keyword Parameters:
        tv -- The tuple of (int,int) for (sec, usec)
        comp_id -- The integer component ID
        ptn_id -- The integer pattern ID
        """
        return self._iterFind(1, **kwargs)

    def iterFindRev(self, **kwargs):
        """Find the message in a forward direction

        Postion the iterator at the message matching the given key (tv, comp_id,
        ptn_id). If such key is not found, position the iterator at the previous
        nearest message (reverse direction).

        Keyword Parameters:
        tv -- The tuple of (int,int) for (sec, usec)
        comp_id -- The integer component ID
        ptn_id -- The integer pattern ID
        """
        return self._iterFind(0, **kwargs)

    @cython.cdivision(True)
    def count(self, ptn_id, start_time = None, end_time = None):
        """Return the number of messages matching a condition

        Positional Parameters:
        -- The id for the pattern this message matches

        Keyword Parameters:
        start_time -- The Unix timestamp of the first message
        end_time   -- The Unix timestamp of the last message
        """
        cdef uint32_t start, end, delta, bin_width
        cdef Bs.bptn_hist_iter_t it
        cdef Bs.bptn_hist_s hist
        cdef size_t msg_count
        cdef Bmsg m
        cdef Bs.bstore_iter_filter_s c_filter
        cdef int rc

        if ptn_id >= 256 and not start_time and not end_time:
            # need no iteration, just return the pattern.msg_count
            ptn = self.store.ptn_by_id(ptn_id)
            return ptn.msg_count()

        c_filter.tv_begin.tv_sec = 0
        c_filter.tv_begin.tv_usec = 0
        c_filter.tv_end.tv_sec = 0
        c_filter.tv_end.tv_usec = 0
        c_filter.ptn_id = ptn_id if ptn_id else 1
        c_filter.bin_width = 60 # may change to 3600 later

        it = Bs.bstore_ptn_hist_iter_new(self.store.c_store)
        Bs.bstore_ptn_hist_iter_filter_set(it, &c_filter)

        if not start_time:
            rc = Bs.bstore_ptn_hist_iter_first(it)
            if rc:
                Bs.bstore_ptn_hist_iter_free(it)
                return 0 # no entry
            Bs.bstore_ptn_hist_iter_obj(it, &hist)
            start = hist.time
        else:
            start = start_time

        if not end_time:
            rc = Bs.bstore_ptn_hist_iter_last(it)
            if rc:
                Bs.bstore_ptn_hist_iter_free(it)
                return 0 # no entry
            Bs.bstore_ptn_hist_iter_obj(it, &hist)
            end = hist.time
        else:
            end = end_time

        delta = end - start
        if delta > 3600:
            bin_width = 3600
        else:
            bin_width = 60

        start = start - (start % bin_width)
        end += bin_width - 1
        end = end - (end % bin_width)
        c_filter.tv_begin.tv_sec = start
        c_filter.tv_end.tv_sec = end
        c_filter.bin_width = bin_width

        Bs.bstore_ptn_hist_iter_filter_set(it, &c_filter)

        msg_count = 0
        rc = Bs.bstore_ptn_hist_iter_first(it)
        while rc == 0:
            Bs.bstore_ptn_hist_iter_obj(it, &hist)
            if hist.time >= end:
                break
            msg_count += hist.msg_count
            rc = Bs.bstore_ptn_hist_iter_next(it)
        Bs.bstore_ptn_hist_iter_free(it)

        return msg_count


cdef class Bptn_hist:
    cdef Bs.bptn_hist_s c_hist

    def ptn_id(self):
        return self.c_hist.ptn_id

    def bin_width(self):
        return self.c_hist.bin_width

    def time(self):
        return self.c_hist.time

    def msg_count(self):
        return self.c_hist.msg_count

    def __str__(self):
        return "(%d, %d, %d, %d)" % (self.c_hist.bin_width,
                                 self.c_hist.time,
                                 self.c_hist.ptn_id,
                                 self.c_hist.msg_count)

cdef int __bin_width__(s):
    bw = s.upper()
    if bw == 'D':
        return 86400
    elif bw == 'H':
        return 3600
    elif bw == 'M':
        return 60
    raise ValueError("A bin-width specification must be one of: " \
                     "d, h, or m for Days, Hours, Minutes")


cdef class Bptn_hist_iter(Biter):
    """Pattern History Iterator"""
    cdef Bs.bptn_hist_s c_ptn_h

    def __init__(self, Bstore store):
        Biter.__init__(self, store)

    cdef Bs.bstore_iter_t iterNew(self):
        return Bs.bstore_ptn_hist_iter_new(self.store.c_store)

    cdef void iterDel(self):
        Bs.bstore_ptn_hist_iter_free(self.c_iter)

    cdef object obj_wrap(self, void *c_obj):
        ptn_h = Bptn_hist()
        ptn_h.c_hist = (<Bs.bptn_hist_t>c_obj)[0]
        return ptn_h

    cdef void *iterObj(self):
        return Bs.bstore_ptn_hist_iter_obj(self.c_iter, &self.c_ptn_h)

    cdef int iterFirst(self):
        return Bs.bstore_ptn_hist_iter_first(self.c_iter)

    cdef int iterNext(self):
        return Bs.bstore_ptn_hist_iter_next(self.c_iter)

    cdef int iterPrev(self):
        return Bs.bstore_ptn_hist_iter_prev(self.c_iter)

    cdef int iterLast(self):
        return Bs.bstore_ptn_hist_iter_last(self.c_iter)

    cdef int iterFilterSet(self, Bs.bstore_iter_filter_t f):
        return Bs.bstore_ptn_hist_iter_filter_set(self.c_iter, f)

    def duration(self):
        cdef int rc
        cdef Bs.bptn_hist_t h

        rc = Bs.bstore_ptn_hist_iter_first(self.c_iter)
        assert(rc == 0)
        h = Bs.bstore_ptn_hist_iter_obj(self.c_iter, &self.c_ptn_h)
        start = h.time

        rc = Bs.bstore_ptn_hist_iter_last(self.c_iter)
        assert(rc == 0)
        h = Bs.bstore_ptn_hist_iter_obj(self.c_iter, &self.c_ptn_h)
        end = h.time

        return end - start

    def as_xy_arrays(self, ptn_id, bin_width, start_time=None, end_time=None):
        # cdef int rec_no
        # cdef int rc
        # cdef void *c_obj

        # x = Array.Array()
        # y = Array.Array()
        # rc = Bs.bstore_ptn_hist_iter_first(self.c_iter)
        # rec_no = 0
        # while rc == 0:
        #     c_obj = Bs.bstore_ptn_hist_iter_obj(self.c_iter, &self.c_ptn_h)
        #     assert(c_obj)
        #     x.append(self.c_ptn_h.time)
        #     y.append(self.c_ptn_h.msg_count)
        #     rec_no += 1
        #     rc = Bs.bstore_ptn_hist_iter_next(self.c_iter)
        # return (rec_no, x.as_ndarray(), y.as_ndarray())
        return None

cdef class Bcomp_hist:
    cdef Bs.bcomp_hist_s c_hist

    def comp_id(self):
        return self.c_hist.comp_id

    def ptn_id(self):
        return self.c_hist.ptn_id

    def bin_width(self):
        return self.c_hist.bin_width

    def time(self):
        return self.c_hist.time

    def msg_count(self):
        return self.c_hist.msg_count

    def __str__(self):
        return "(%d, %d, %d, %d, %d)" % (self.c_hist.bin_width,
                                 self.c_hist.time,
                                 self.c_hist.comp_id,
                                 self.c_hist.ptn_id,
                                 self.c_hist.msg_count)

cdef class Bcomp_hist_iter(Biter):
    """Component History Iterator"""
    cdef Bs.bcomp_hist_s c_comp_h

    def __init__(self, Bstore store):
        Biter.__init__(self, store)

    cdef Bs.bstore_iter_t iterNew(self):
        return Bs.bstore_comp_hist_iter_new(self.store.c_store)

    cdef void iterDel(self):
        Bs.bstore_comp_hist_iter_free(self.c_iter)

    cdef object obj_wrap(self, void *c_obj):
        comp_h = Bcomp_hist()
        comp_h.c_hist = (<Bs.bcomp_hist_t>c_obj)[0]
        return comp_h

    cdef void *iterObj(self):
        return Bs.bstore_comp_hist_iter_obj(self.c_iter, &self.c_comp_h)

    cdef int iterFirst(self):
        return Bs.bstore_comp_hist_iter_first(self.c_iter)

    cdef int iterNext(self):
        return Bs.bstore_comp_hist_iter_next(self.c_iter)

    cdef int iterPrev(self):
        return Bs.bstore_comp_hist_iter_prev(self.c_iter)

    cdef int iterLast(self):
        return Bs.bstore_comp_hist_iter_last(self.c_iter)

    cdef int iterFilterSet(self, Bs.bstore_iter_filter_t f):
        return Bs.bstore_comp_hist_iter_filter_set(self.c_iter, f)

    cdef make_hist(self, Bs.bcomp_hist_t hist, kwargs):
        try:
            kw_tv = kwargs["tv"]
            hist.time =  kw_tv[0]
        except:
            hist.time = 0
        try:
            hist.comp_id = kwargs["comp_id"]
        except:
            hist.comp_id = 0
        try:
            hist.ptn_id = kwargs["ptn_id"]
        except:
            hist.ptn_id = 0
        try:
            hist.bin_width = kwargs["bin_width"]
        except:
            hist.bin_width = 3600

    def _iterFind(self, fwd, **kwargs):
        cdef Bs.timeval tval
        cdef Bs.timeval *tv
        cdef Bs.bcomp_hist_s c_hist
        self.make_hist(&c_hist, kwargs)
        if fwd:
            return Bs.bstore_comp_hist_iter_find_fwd(self.c_iter, &c_hist)
        else:
            return Bs.bstore_comp_hist_iter_find_rev(self.c_iter, &c_hist)

    def iterFindFwd(self, **kwargs):
        return self._iterFind(self, 1, **kwargs)

    def iterFindRev(self, **kwargs):
        return self._iterFind(self, 0, **kwargs)

    def duration(self, comp_id, start=None):
        cdef Bs.bcomp_hist_t h
        cdef int rc

        rc = Bs.bstore_comp_hist_iter_first(self.c_iter)
        assert(rc == 0)
        h = Bs.bstore_comp_hist_iter_obj(self.c_iter, &self.c_comp_h)
        start = h.time

        rc = Bs.bstore_comp_hist_iter_last(self.c_iter)
        assert(rc == 0)
        h = Bs.bstore_comp_hist_iter_obj(self.c_iter, &self.c_comp_h)
        end = h.time

        return end - start

    def as_xy_arrays(self):
        # cdef int rec_no
        # cdef int rc
        # cdef void *c_obj

        # rec_no = 0
        # x = Array.Array()
        # y = Array.Array()

        # rc = Bs.bstore_comp_hist_iter_first(self.c_iter)
        # while rc == 0:
        #     c_obj = Bs.bstore_comp_hist_iter_obj(self.c_iter, &self.c_comp_h)
        #     assert(c_obj)
        #     x.append(self.c_comp_h.time)
        #     y.append(self.c_comp_h.msg_count)
        #     rec_no += 1
        #     rc = Bs.bstore_comp_hist_iter_next(self.c_iter)
        # return (rec_no, x.as_ndarray(), y.as_ndarray())
        return None

cdef class Btkn_hist:
    cdef Bs.btkn_hist_s c_hist

    def tkn_id(self):
        return self.c_hist.tkn_id

    def bin_width(self):
        return self.c_hist.bin_width

    def time(self):
        return self.c_hist.time

    def tkn_count(self):
        return self.c_hist.tkn_count

    def __str__(self):
        return "(%d, %d, %d, %d)" % (self.c_hist.bin_width,
                                 self.c_hist.time,
                                 self.c_hist.tkn_id,
                                 self.c_hist.tkn_count)

cdef class Btkn_hist_iter(Biter):
    """Btkn History Iterator"""
    cdef Bs.btkn_hist_s c_tkn_h

    def __init__(self, Bstore store):
        Biter.__init__(self, store)

    cdef Bs.bstore_iter_t iterNew(self):
        return Bs.bstore_tkn_hist_iter_new(self.store.c_store)

    cdef void iterDel(self):
        Bs.bstore_tkn_hist_iter_free(self.c_iter)

    cdef object obj_wrap(self, void *c_obj):
        tkn_h = Btkn_hist()
        tkn_h.c_hist = (<Bs.btkn_hist_t>c_obj)[0]
        return tkn_h

    cdef void *iterObj(self):
        return Bs.bstore_tkn_hist_iter_obj(self.c_iter, &self.c_tkn_h)
    cdef int iterFirst(self):
        return Bs.bstore_tkn_hist_iter_first(self.c_iter)

    cdef int iterNext(self):
        return Bs.bstore_tkn_hist_iter_next(self.c_iter)

    cdef int iterPrev(self):
        return Bs.bstore_tkn_hist_iter_prev(self.c_iter)

    cdef int iterLast(self):
        return Bs.bstore_tkn_hist_iter_last(self.c_iter)

    cdef make_hist(self, Bs.btkn_hist_t hist, kwargs):
        try:
            kw_tv = kwargs["tv"]
            hist.time =  kw_tv[0]
        except:
            hist.time = 0
        try:
            hist.tkn_id = kwargs["tkn_id"]
        except:
            hist.tkn_id = 0
        try:
            hist.bin_width = kwargs["bin_width"]
        except:
            hist.bin_width = 3600

    def _iterFind(self, fwd, **kwargs):
        cdef Bs.timeval tval
        cdef Bs.timeval *tv
        cdef Bs.btkn_hist_s c_hist
        self.make_hist(&c_hist, kwargs)
        if fwd:
            return Bs.bstore_tkn_hist_iter_find_fwd(self.c_iter, &c_hist)
        else:
            return Bs.bstore_tkn_hist_iter_find_rev(self.c_iter, &c_hist)

    def iterFindFwd(self, **kwargs):
        return self._iterFind(self, 1, **kwargs)

    def iterFindRev(self, **kwargs):
        return self._iterFind(self, 0, **kwargs)

    cdef int iterFilterSet(self, Bs.bstore_iter_filter_t f):
        return Bs.bstore_tkn_hist_iter_filter_set(self.c_iter, f)

    def duration(self):
        """Return the duration (restricted by filter) in seconds of the token
           history
        """
        cdef int rc
        cdef Bs.btkn_hist_t h

        rc = Bs.bstore_tkn_hist_iter_first(self.c_iter)
        assert(rc == 0)
        h = Bs.bstore_tkn_hist_iter_obj(self.c_iter, &self.c_tkn_h)
        start = h.time

        rc = Bs.bstore_tkn_hist_iter_last(self.c_iter)
        assert(rc == 0)
        h = Bs.bstore_tkn_hist_iter_obj(self.c_iter, &self.c_tkn_h)
        end = h.time

        return end - start

    def as_xy_arrays(self, **kwargs):
        # cdef int rec_no
        # cdef int rc
        # cdef void *c_obj
        # x = Array.Array()
        # y = Array.Array()
        # rc = Bs.bstore_tkn_hist_iter_first(self.c_iter)
        # rec_no = 0
        # while rc == 0:
        #     c_obj = Bs.bstore_tkn_hist_iter_obj(self.c_iter, &self.c_tkn_h)
        #     assert(c_obj)
        #     x.append(self.c_tkn_h.time)
        #     y.append(self.c_tkn_h.tkn_count)
        #     rec_no += 1
        #     rc = Bs.bstore_tkn_hist_iter_next(self.c_iter)
        # return (rec_no, x.as_ndarray(), y.as_ndarray())
        return None
