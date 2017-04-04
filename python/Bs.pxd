import cython
cimport numpy as np

cdef extern from "inttypes.h":
    ctypedef unsigned int uint32_t
    ctypedef unsigned long uint64_t

cdef extern from "fcntl.h":
    cdef int O_CREAT
    cdef int O_RDWR

cdef extern from "sys/time.h":
    ctypedef unsigned long time_t
    cdef struct timeval:
        time_t tv_sec
        time_t tv_usec
    ctypedef timeval *timeval_t

cdef extern from "baler/btkn_types.h":
    ctypedef uint64_t btkn_type_t
    cdef int BTKN_TYPE_TYPE
    cdef int BTKN_TYPE_PRIORITY
    cdef int BTKN_TYPE_VERSION
    cdef int BTKN_TYPE_TIMESTAMP
    cdef int BTKN_TYPE_HOSTNAME
    cdef int BTKN_TYPE_SERVICE
    cdef int BTKN_TYPE_PID
    cdef int BTKN_TYPE_IP4_ADDR
    cdef int BTKN_TYPE_IP6_ADDR
    cdef int BTKN_TYPE_ETH_ADDR
    cdef int BTKN_TYPE_HEX_INT
    cdef int BTKN_TYPE_DEC_INT
    cdef int BTKN_TYPE_SEPARATOR
    cdef int BTKN_TYPE_FLOAT
    cdef int BTKN_TYPE_PATH
    cdef int BTKN_TYPE_URL
    cdef int BTKN_TYPE_WORD
    cdef int BTKN_TYPE_TEXT
    cdef int BTKN_TYPE_WHITESPACE
    cdef int BTKN_TYPE_LAST

cdef extern from "baler/btypes.h":

    ctypedef struct bstr:
        unsigned int blen
        char cstr[0]
        uint32_t u32str[0]
        uint64_t u64str[0]

    ctypedef bstr *bstr_t

    ctypedef uint64_t btkn_id_t
    ctypedef uint64_t btkn_type_mask_t
    cdef struct btkn:
        btkn_id_t tkn_id
        btkn_type_mask_t tkn_type_mask
        uint64_t tkn_count
        bstr_t tkn_str
    ctypedef btkn *btkn_t

    ctypedef uint64_t bptn_id_t
    ctypedef struct bptn:
        bptn_id_t ptn_id
        timeval first_seen
        timeval last_seen
        uint64_t count
        uint64_t tkn_count
        bstr_t str
    ctypedef bptn *bptn_t

    ctypedef uint64_t bcomp_id_t
    ctypedef struct bmsg:
        bptn_id_t ptn_id
        bcomp_id_t comp_id
        timeval timestamp
        uint32_t  argc
        btkn_id_t argv[0]
    ctypedef bmsg *bmsg_t

cdef extern from "baler/bstore.h":
    ctypedef struct bstore_s
    ctypedef bstore_s *bstore_t
    bstore_t bstore_open(const char *plugin, const char *path, int flags, ...)
    void bstore_close(bstore_t bs)

    ctypedef struct bstore_iter_s
    ctypedef bstore_iter_s *bstore_iter_t
    ctypedef void *bstore_iter_pos_t

    btkn_t btkn_alloc(btkn_id_t tkn_id, btkn_type_mask_t mask, const char *str, size_t len)
    btkn_t btkn_dup(btkn_t src)
    void btkn_free(btkn_t)
    int btkn_has_type(btkn_t tkn, btkn_type_t typ)
    btkn_type_t btkn_first_type(btkn_t tkn)

    btkn_t bstore_tkn_find_by_id(bstore_t bs, btkn_id_t tkn_id)
    btkn_t bstore_tkn_find_by_name(bstore_t bs, const char *name, size_t name_len)

    bmsg_t bmsg_dup(bmsg_t src)
    void bmsg_free(bmsg_t msg)
    bptn_t bptn_alloc(size_t tkn_count)
    void bptn_free(bptn_t ptn)

    ctypedef bstore_iter_t btkn_iter_t
    btkn_iter_t bstore_tkn_iter_new(bstore_t bs)
    bstore_iter_pos_t bstore_tkn_iter_pos(btkn_iter_t)
    int bstore_tkn_iter_pos_set(btkn_iter_t, bstore_iter_pos_t)
    btkn_iter_t bstore_tkn_iter_new(bstore_t bs)
    void bstore_tkn_iter_free(btkn_iter_t i)
    unsigned long bstore_tkn_iter_card(btkn_iter_t i)
    btkn_t bstore_tkn_iter_first(btkn_iter_t iter)
    btkn_t bstore_tkn_iter_obj(btkn_iter_t iter)
    btkn_t bstore_tkn_iter_next(btkn_iter_t iter)
    btkn_t bstore_tkn_iter_prev(btkn_iter_t iter)
    btkn_t bstore_tkn_iter_last(btkn_iter_t iter)

    bptn_t bstore_ptn_find(bstore_t bs, bptn_id_t ptn_id)
    bstore_iter_t bstore_ptn_iter_new(bstore_t bs)
    void bstore_ptn_iter_free(bstore_iter_t iter)
    unsigned long bstore_ptn_iter_card(bstore_iter_t i)
    bptn_t bstore_ptn_iter_obj(bstore_iter_t iter)
    bptn_t bstore_ptn_iter_next(bstore_iter_t iter)
    bptn_t bstore_ptn_iter_prev(bstore_iter_t iter)
    bptn_t bstore_ptn_iter_find(bstore_iter_t iter, time_t start)
    bptn_t bstore_ptn_iter_first(bstore_iter_t iter)
    bptn_t bstore_ptn_iter_last(bstore_iter_t iter)
    bstore_iter_pos_t bstore_ptn_iter_pos(btkn_iter_t)
    int bstore_ptn_iter_pos_set(btkn_iter_t, bstore_iter_pos_t)

    bstore_iter_pos_t bstore_msg_iter_pos(bstore_iter_t)
    int bstore_msg_iter_pos_set(bstore_iter_t, bstore_iter_pos_t)
    bstore_iter_t bstore_msg_iter_new(bstore_t bs)
    void bstore_msg_iter_free(bstore_iter_t i)
    uint64_t bstore_msg_iter_card(bstore_iter_t i)
    ctypedef int (*bmsg_cmp_fn_t)(bptn_id_t ptn_id, time_t ts,
                                            bcomp_id_t comp_id, void *ctxt)
    bmsg_t bstore_msg_iter_find(bstore_iter_t i,
                            bptn_id_t ptn_id, time_t start, bcomp_id_t comp_id,
                            bmsg_cmp_fn_t cmp_fn, void *ctxt)
    bmsg_t bstore_msg_iter_obj(bstore_iter_t i)
    bmsg_t bstore_msg_iter_next(bstore_iter_t i)
    bmsg_t bstore_msg_iter_prev(bstore_iter_t i)
    bmsg_t bstore_msg_iter_first(bstore_iter_t i)
    bmsg_t bstore_msg_iter_last(bstore_iter_t i)

    char *bstore_pos_to_str(bstore_iter_pos_t pos)
    bstore_iter_pos_t bstore_pos_from_str(const char *pos)
    void bstore_iter_pos_free(bstore_iter_t iter, bstore_iter_pos_t pos)

    cdef struct bptn_hist_s:
        bptn_id_t ptn_id
        uint32_t bin_width
        uint32_t time
        uint64_t msg_count
    ctypedef bptn_hist_s *bptn_hist_t

    ctypedef bstore_iter_t bptn_iter_t
    ctypedef bstore_iter_t bptn_hist_iter_t

    cdef bstore_iter_pos_t bstore_ptn_hist_iter_pos(bptn_hist_iter_t)
    cdef int bstore_ptn_hist_iter_pos_set(bptn_hist_iter_t, bstore_iter_pos_t)
    cdef bptn_hist_iter_t bstore_ptn_hist_iter_new(bstore_t bs)
    cdef void bstore_ptn_hist_iter_free(bptn_hist_iter_t it)
    cdef bptn_hist_t bstore_ptn_hist_iter_find(bptn_hist_iter_t it, bptn_hist_t ptn_h)
    cdef bptn_hist_t bstore_ptn_hist_iter_obj(bptn_hist_iter_t it, bptn_hist_t ptn_h)
    cdef bptn_hist_t bstore_ptn_hist_iter_next(bptn_hist_iter_t it, bptn_hist_t ptn_h)
    cdef bptn_hist_t bstore_ptn_hist_iter_first(bptn_hist_iter_t it, bptn_hist_t ptn_h)
    cdef bptn_hist_t bstore_ptn_hist_iter_last(bptn_hist_iter_t it, bptn_hist_t ptn_h)

    ctypedef bstore_iter_t bptn_tkn_iter_t
    cdef btkn_t bstore_ptn_tkn_find(bstore_t bs,
                                    bptn_id_t ptn_id, uint64_t tkn_pos,
                                    btkn_id_t tkn_id)
    cdef bstore_iter_pos_t bstore_ptn_tkn_iter_pos(bptn_tkn_iter_t)
    cdef int bstore_ptn_tkn_iter_pos_set(bptn_tkn_iter_t, bstore_iter_pos_t)
    cdef bptn_tkn_iter_t bstore_ptn_tkn_iter_new(bstore_t bs)
    cdef void bstore_ptn_tkn_iter_free(bptn_tkn_iter_t it)
    cdef uint64_t bstore_ptn_tkn_iter_card(bptn_tkn_iter_t it)
    cdef btkn_t bstore_ptn_tkn_iter_find(bptn_tkn_iter_t it, bptn_id_t ptn_id, uint64_t pos)
    cdef btkn_t bstore_ptn_tkn_iter_obj(bptn_tkn_iter_t it)
    cdef btkn_t bstore_ptn_tkn_iter_next(bptn_tkn_iter_t it)
    cdef btkn_t bstore_ptn_tkn_iter_prev(bptn_tkn_iter_t it)

    cdef struct btkn_hist_s:
        btkn_id_t tkn_id
        uint32_t bin_width
        uint32_t time
        uint64_t tkn_count
    ctypedef btkn_hist_s *btkn_hist_t

    ctypedef bstore_iter_t btkn_hist_iter_t
    bstore_iter_pos_t bstore_tkn_hist_iter_pos(btkn_hist_iter_t)
    int bstore_tkn_hist_iter_pos_set(btkn_hist_iter_t, bstore_iter_pos_t)
    btkn_hist_iter_t bstore_tkn_hist_iter_new(bstore_t bs)
    void bstore_tkn_hist_iter_free(btkn_hist_iter_t iter)
    btkn_hist_t bstore_tkn_hist_iter_find(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
    btkn_hist_t bstore_tkn_hist_iter_obj(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
    btkn_hist_t bstore_tkn_hist_iter_next(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
    btkn_hist_t bstore_tkn_hist_iter_first(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
    btkn_hist_t bstore_tkn_hist_iter_last(btkn_hist_iter_t iter, btkn_hist_t tkn_h)

    cdef struct bcomp_hist_s:
        bcomp_id_t comp_id
        bptn_id_t ptn_id
        uint32_t bin_width
        uint32_t time
        uint64_t msg_count
    ctypedef bcomp_hist_s *bcomp_hist_t
    ctypedef bstore_iter_t bcomp_hist_iter_t

    bstore_iter_pos_t bstore_comp_hist_iter_pos(bcomp_hist_iter_t)
    int bstore_comp_hist_iter_pos_set(bcomp_hist_iter_t, bstore_iter_pos_t)
    bcomp_hist_iter_t bstore_comp_hist_iter_new(bstore_t bs)
    void bstore_comp_hist_iter_free(bcomp_hist_iter_t iter)
    bcomp_hist_t bstore_comp_hist_iter_find(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
    bcomp_hist_t bstore_comp_hist_iter_obj(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
    bcomp_hist_t bstore_comp_hist_iter_next(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
    bcomp_hist_t bstore_comp_hist_iter_first(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
    bcomp_hist_t bstore_comp_hist_iter_last(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)

cdef extern from "baler/btkn.h":
    uint64_t btkn_type_mask_from_str(const char *str)
