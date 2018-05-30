import cython

cdef extern from "strings.h":
    void bzero(void *s, size_t n)

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
    ctypedef timeval timeval_s

cdef extern from "baler/btkn_types.h":
    ctypedef uint64_t btkn_type_t
    cdef int BTKN_TYPE_FIRST
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
    cdef int BTKN_TYPE_NUMBER
    cdef int BTKN_TYPE_SEPARATOR
    cdef int BTKN_TYPE_FLOAT
    cdef int BTKN_TYPE_PATH
    cdef int BTKN_TYPE_URL
    cdef int BTKN_TYPE_WORD
    cdef int BTKN_TYPE_TEXT
    cdef int BTKN_TYPE_WHITESPACE
    cdef int BTKN_TYPE_LAST_BUILTIN
    cdef int BTKN_TYPE_FIRST_USER
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
    bptn_t bptn_dup(bptn_t ptn)

    cdef struct bptn_attr_s:
        bptn_id_t ptn_id
        char *attr_type
        char *attr_value
        char _data[0]
    ctypedef bptn_attr_s *bptn_attr_t
    void bptn_attr_free(bptn_attr_t)

cdef extern from "baler/bstore.h":
    cdef struct bstore_s
    ctypedef uint64_t bstore_iter_pos_t
    ctypedef bstore_s *bstore_t
    bstore_t bstore_open(const char *plugin, const char *path, int flags, ...)
    void bstore_close(bstore_t bs)

    ctypedef struct bstore_iter_s
    ctypedef bstore_iter_s *bstore_iter_t

    cdef struct bstore_iter_filter_s:
        timeval tv_begin
        timeval tv_end
        bptn_id_t ptn_id
        bcomp_id_t comp_id
        btkn_id_t tkn_id
        uint64_t tkn_pos
        uint64_t bin_width
        const char *attr_type
        const char *attr_value

    ctypedef bstore_iter_filter_s *bstore_iter_filter_t

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
    void bstore_tkn_iter_free(btkn_iter_t i)
    unsigned long bstore_tkn_iter_card(btkn_iter_t i)
    btkn_t bstore_tkn_iter_obj(btkn_iter_t iter)
    int bstore_tkn_iter_first(btkn_iter_t iter)
    int bstore_tkn_iter_next(btkn_iter_t iter)
    int bstore_tkn_iter_prev(btkn_iter_t iter)
    int bstore_tkn_iter_last(btkn_iter_t iter)

    bptn_t bstore_ptn_find(bstore_t bs, bptn_id_t ptn_id)
    bstore_iter_t bstore_ptn_iter_new(bstore_t bs)
    void bstore_ptn_iter_free(bstore_iter_t iter)
    unsigned long bstore_ptn_iter_card(bstore_iter_t i)
    bptn_t bstore_ptn_iter_obj(bstore_iter_t iter)
    int bstore_ptn_iter_find_fwd(bstore_iter_t iter, bptn_id_t ptn_id)
    int bstore_ptn_iter_find_rev(bstore_iter_t iter, bptn_id_t ptn_id)
    int bstore_ptn_iter_next(bstore_iter_t iter)
    int bstore_ptn_iter_prev(bstore_iter_t iter)
    int bstore_ptn_iter_first(bstore_iter_t iter)
    int bstore_ptn_iter_last(bstore_iter_t iter)
    int bstore_ptn_iter_filter_set(bstore_iter_t i, bstore_iter_filter_t f)

    bstore_iter_t bstore_msg_iter_new(bstore_t bs)
    void bstore_msg_iter_free(bstore_iter_t i)
    uint64_t bstore_msg_iter_card(bstore_iter_t i)
    bmsg_t bstore_msg_iter_obj(bstore_iter_t i)
    int bstore_msg_iter_find_fwd(bstore_iter_t itr, timeval *tv,
                                 bcomp_id_t comp_id, bptn_id_t ptn_id)
    int bstore_msg_iter_find_rev(bstore_iter_t itr, timeval *tv,
                                 bcomp_id_t comp_id, bptn_id_t ptn_id)
    int bstore_msg_iter_next(bstore_iter_t i)
    int bstore_msg_iter_prev(bstore_iter_t i)
    int bstore_msg_iter_first(bstore_iter_t i)
    int bstore_msg_iter_last(bstore_iter_t i)
    int bstore_msg_iter_filter_set(bstore_iter_t i, bstore_iter_filter_t f)

    cdef struct bptn_hist_s:
        bptn_id_t ptn_id
        uint32_t bin_width
        uint32_t time
        uint64_t msg_count
    ctypedef bptn_hist_s *bptn_hist_t

    ctypedef bstore_iter_t bptn_iter_t
    ctypedef bstore_iter_t bptn_hist_iter_t

    cdef bptn_hist_iter_t bstore_ptn_hist_iter_new(bstore_t bs)
    cdef void bstore_ptn_hist_iter_free(bptn_hist_iter_t it)
    cdef bptn_hist_t bstore_ptn_hist_iter_obj(bptn_hist_iter_t it, bptn_hist_t ptn_h)
    int bstore_ptn_hist_iter_filter_set(bptn_hist_iter_t iter,
                                        bstore_iter_filter_t filter)
    cdef int bstore_ptn_hist_iter_find_fwd(bptn_hist_iter_t it, bptn_hist_t ptn_h)
    cdef int bstore_ptn_hist_iter_find_rev(bptn_hist_iter_t it, bptn_hist_t ptn_h)
    cdef int bstore_ptn_hist_iter_first(bptn_hist_iter_t it)
    cdef int bstore_ptn_hist_iter_next(bptn_hist_iter_t it)
    cdef int bstore_ptn_hist_iter_prev(bptn_hist_iter_t it)
    cdef int bstore_ptn_hist_iter_last(bptn_hist_iter_t it)

    ctypedef bstore_iter_t bptn_tkn_iter_t
    cdef btkn_t bstore_ptn_tkn_find(bstore_t bs,
                                    bptn_id_t ptn_id, uint64_t tkn_pos,
                                    btkn_id_t tkn_id)
    cdef bptn_tkn_iter_t bstore_ptn_tkn_iter_new(bstore_t bs);
    cdef void bstore_ptn_tkn_iter_free(bptn_tkn_iter_t it)
    cdef uint64_t bstore_ptn_tkn_iter_card(bptn_tkn_iter_t it)
    cdef btkn_t bstore_ptn_tkn_iter_obj(bptn_tkn_iter_t it)
    cdef int bstore_ptn_tkn_iter_next(bptn_tkn_iter_t it)
    cdef int bstore_ptn_tkn_iter_prev(bptn_tkn_iter_t it)
    cdef int bstore_ptn_tkn_iter_first(bptn_tkn_iter_t it)
    cdef int bstore_ptn_tkn_iter_last(bptn_tkn_iter_t it)
    cdef int bstore_ptn_tkn_iter_filter_set(bptn_tkn_iter_t itr,
                                            bstore_iter_filter_t fltr);

    cdef struct btkn_hist_s:
        btkn_id_t tkn_id
        uint32_t bin_width
        uint32_t time
        uint64_t tkn_count
    ctypedef btkn_hist_s *btkn_hist_t

    ctypedef bstore_iter_t btkn_hist_iter_t
    btkn_hist_iter_t bstore_tkn_hist_iter_new(bstore_t bs)
    void bstore_tkn_hist_iter_free(btkn_hist_iter_t iter)
    btkn_hist_t bstore_tkn_hist_iter_obj(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
    int bstore_tkn_hist_iter_filter_set(btkn_hist_iter_t iter,
                                        bstore_iter_filter_t filter)
    int bstore_tkn_hist_iter_find_fwd(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
    int bstore_tkn_hist_iter_find_rev(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
    int bstore_tkn_hist_iter_first(btkn_hist_iter_t iter)
    int bstore_tkn_hist_iter_next(btkn_hist_iter_t iter)
    int bstore_tkn_hist_iter_prev(btkn_hist_iter_t iter)
    int bstore_tkn_hist_iter_last(btkn_hist_iter_t iter)

    cdef struct bcomp_hist_s:
        bcomp_id_t comp_id
        bptn_id_t ptn_id
        uint32_t bin_width
        uint32_t time
        uint64_t msg_count
    ctypedef bcomp_hist_s *bcomp_hist_t
    ctypedef bstore_iter_t bcomp_hist_iter_t

    bcomp_hist_iter_t bstore_comp_hist_iter_new(bstore_t bs)
    void bstore_comp_hist_iter_free(bcomp_hist_iter_t iter)
    bcomp_hist_t bstore_comp_hist_iter_obj(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
    int bstore_comp_hist_iter_filter_set(bcomp_hist_iter_t iter,
                                         bstore_iter_filter_t filter)
    int bstore_comp_hist_iter_find_fwd(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
    int bstore_comp_hist_iter_find_rev(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
    int bstore_comp_hist_iter_first(bcomp_hist_iter_t iter)
    int bstore_comp_hist_iter_next(bcomp_hist_iter_t iter)
    int bstore_comp_hist_iter_prev(bcomp_hist_iter_t iter)
    int bstore_comp_hist_iter_last(bcomp_hist_iter_t iter)

    bstore_iter_pos_t bstore_iter_pos_get(bstore_iter_t iter)
    int bstore_iter_pos_set(bstore_iter_t iter, bstore_iter_pos_t pos_h)
    void bstore_iter_pos_free(bstore_iter_t iter, bstore_iter_pos_t pos_h)
    char *bstore_pos_to_str(bstore_iter_pos_t pos)
    bstore_iter_pos_t bstore_pos_from_str(const char *pos)

    int bstore_attr_new(bstore_t bs, const char *attr_type)
    int bstore_attr_find(bstore_t bs, const char *attr_type)
    int bstore_ptn_attr_value_set(bstore_t bs, bptn_id_t ptn_id,
            const char *attr_type, const char *attr_value)
    int bstore_ptn_attr_value_add(bstore_t bs, bptn_id_t ptn_id,
            const char *attr_type, const char *attr_value)
    int bstore_ptn_attr_value_rm(bstore_t bs, bptn_id_t ptn_id,
            const char *attr_type, const char *attr_value)
    int bstore_ptn_attr_unset(bstore_t bs, bptn_id_t ptn_id,
            const char *attr_type)
    char *bstore_ptn_attr_get(bstore_t bs, bptn_id_t ptn_id,
            const char *attr_type)

    # ptn_attr_iter
    ctypedef bstore_iter_t bptn_attr_iter_t
    bptn_attr_iter_t bstore_ptn_attr_iter_new(bstore_t bs)
    void bstore_ptn_attr_iter_free(bptn_attr_iter_t iter)
    int bstore_ptn_attr_iter_filter_set(bptn_attr_iter_t iter,
                                     bstore_iter_filter_t filter)
    bptn_attr_t bstore_ptn_attr_iter_obj(bptn_attr_iter_t iter)
    int bstore_ptn_attr_iter_find_fwd(bptn_attr_iter_t iter,
                                  bptn_id_t ptn_id,
                                  const char *attr_type,
                                  const char *attr_value)
    int bstore_ptn_attr_iter_find_rev(bptn_attr_iter_t iter,
                                  bptn_id_t ptn_id,
                                  const char *attr_type,
                                  const char *attr_value)
    int bstore_ptn_attr_iter_first(bptn_attr_iter_t iter)
    int bstore_ptn_attr_iter_next(bptn_attr_iter_t iter)
    int bstore_ptn_attr_iter_prev(bptn_attr_iter_t iter)
    int bstore_ptn_attr_iter_last(bptn_attr_iter_t iter)

    ctypedef bstore_iter_t battr_iter_t
    battr_iter_t bstore_attr_iter_new(bstore_t bs)
    void bstore_attr_iter_free(battr_iter_t iter)
    char *bstore_attr_iter_obj(battr_iter_t iter)
    int bstore_attr_iter_find(battr_iter_t iter, const char *attr_type)
    int bstore_attr_iter_first(battr_iter_t iter)
    int bstore_attr_iter_next(battr_iter_t iter)
    int bstore_attr_iter_prev(battr_iter_t iter)
    int bstore_attr_iter_last(battr_iter_t iter)

#### -- end of "baler/bstore.h" import -- ####


cdef extern from "baler/btkn.h":
    uint64_t btkn_type_mask_from_str(const char *str)

cdef extern from "baler/bmeta.h":
    cdef struct bmc_params_s:
        float diff_ratio
        float looseness
        float refinement_speed
    ctypedef bmc_params_s *bmc_params_t
    ctypedef uint32_t bmc_id_t
    cdef struct bmc_list_s:
        pass
    ctypedef bmc_list_s *bmc_list_t;
    cdef struct bmc_s:
        bmc_id_t meta_id
        bptn_t meta_ptn
    ctypedef bmc_s *bmc_t
    cdef struct bmc_list_iter_s:
        pass
    ctypedef bmc_list_iter_s *bmc_list_iter_t
    bmc_list_iter_t bmc_list_iter_new(bmc_list_t bmc_list)
    bmc_t bmc_list_iter_first(bmc_list_iter_t iter)
    bmc_t bmc_list_iter_next(bmc_list_iter_t iter)
    void bmc_list_iter_free(bmc_list_iter_t iter)
    cdef struct bmc_iter_s:
        pass
    ctypedef bmc_iter_s *bmc_iter_t
    bmc_iter_t bmc_iter_new(bmc_t bmc)
    bptn_t bmc_iter_first(bmc_iter_t iter)
    bptn_t bmc_iter_next(bmc_iter_t iter)
    void bmc_iter_free(bmc_iter_t iter)

    bmc_list_t bmc_list_compute(bstore_t bs, bmc_params_t params)
    void bmc_list_free(bmc_list_t bmc_list)
