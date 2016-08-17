#ifndef __BSTORE_H_
#define __BSTORE_H_

#include "btkn_types.h"
#include "btypes.h"

struct bstore_plugin_s;
typedef struct bstore_s {
	struct bstore_plugin_s *plugin;
	char *path;
} *bstore_t;

#if 0
typedef struct btkn_iter_s {
	bstore_t bs;
} *btkn_iter_t;
typedef struct bptn_iter_s {
	bstore_t bs;
} *bptn_iter_t;
typedef struct bptn_tkn_iter_s {
	bstore_t bs;
} *bptn_tkn_iter_t;
typedef struct bmsg_iter_s {
	bstore_t bs;
} *bmsg_iter_t;
typedef struct btkn_hist_iter_s {
	bstore_t bs;
} *btkn_hist_iter_t;
typedef struct bptn_hist_iter_s {
	bstore_t bs;
} *bptn_hist_iter_t;
typedef struct bcomp_hist_iter_s {
	bstore_t bs;
} *bcomp_hist_iter_t;
#else
typedef struct bstore_iter_s {
	bstore_t bs;
} *bstore_iter_t;
typedef bstore_iter_t bmsg_iter_t;
typedef bstore_iter_t btkn_iter_t;
typedef bstore_iter_t bptn_iter_t;
typedef bstore_iter_t bptn_tkn_iter_t;
typedef bstore_iter_t bcomp_hist_iter_t;
typedef bstore_iter_t bptn_hist_iter_t;
typedef bstore_iter_t btkn_hist_iter_t;
#endif
typedef void *bstore_iter_pos_t;

/**
 * Return !0 if the current iterator object should be returned
 *
 * The iterator will call this function for each message in the
 * iterator and skip it, i.e. not return it to the caller if the
 * callback function returns a value other than zero.
 *
 * \param ptn_id The pattern id of the candidate message
 * \param ts The unix timestamp of the candidate message
 * \param comp_id The component id of the candidate message
 * \param ctxt The <tt>context</tt> parameter passed to the bstore_first_msg() function
 * \return 0 The candidate message is a match
 * \return !0 The candidate message is not a match and should be skipped
 */
typedef int (*bmsg_cmp_fn_t)(bptn_id_t ptn_id, time_t ts,
			     bcomp_id_t comp_id, void *ctxt);
typedef struct bstore_plugin_s {
	bstore_t (*open)(struct bstore_plugin_s *plugin, const char *path,
			 int flags, int o_mode);
	void (*close)(bstore_t bs);
	/**
	 * If the token is not present in the store, add it. In either
	 * case, return it's tkn_id
	 */
	btkn_id_t (*tkn_add)(bstore_t bs, btkn_t tkn);
	/**
	 * Add a token with an id. The token id cannot already exist.
	 */
	int (*tkn_add_with_id)(bstore_t bs, btkn_t tkn);
	/**
	 * Return a btkn_t for the specified id or name and type
	 */
	btkn_t (*tkn_find_by_id)(bstore_t bs, btkn_id_t tkn_id);
	btkn_t (*tkn_find_by_name)(bstore_t bs, const char *name, size_t name_len);
	/**
	 * Create/destroy a token iterator
	 */
	bstore_iter_pos_t (*tkn_iter_pos)(btkn_iter_t);
	int (*tkn_iter_pos_set)(btkn_iter_t, bstore_iter_pos_t);
	btkn_iter_t (*tkn_iter_new)(bstore_t bs);
	void (*tkn_iter_free)(btkn_iter_t i);
	uint64_t (*tkn_iter_card)(btkn_iter_t i);
	/**
	 * Return the first token
	 */
	btkn_t (*tkn_iter_first)(btkn_iter_t iter);
	/**
	 * Return the next token
	 */
	btkn_t (*tkn_iter_next)(btkn_iter_t iter);
	/**
	 * Add the message to the store
	 */
	int (*msg_add)(bstore_t bs, struct timeval *tv, bmsg_t msg);
	bstore_iter_pos_t (*msg_iter_pos)(bmsg_iter_t);
	int (*msg_iter_pos_set)(bmsg_iter_t, bstore_iter_pos_t);
	bmsg_iter_t (*msg_iter_new)(bstore_t bs);
	void (*msg_iter_free)(bmsg_iter_t i);
	uint64_t (*msg_iter_card)(bmsg_iter_t i);
	bmsg_t (*msg_iter_find)(bmsg_iter_t i,
				bptn_id_t ptn_id, time_t start, bcomp_id_t comp_id,
				bmsg_cmp_fn_t cmp_fn, void *ctxt);
	bmsg_t (*msg_iter_next)(bmsg_iter_t i);
	bmsg_t (*msg_iter_prev)(bmsg_iter_t i);
	bmsg_t (*msg_iter_first)(bmsg_iter_t i);
	bmsg_t (*msg_iter_last)(bmsg_iter_t i);
	/**
	 * Add the pattern to the store
	 */
	bptn_id_t (*ptn_add)(bstore_t bs, struct timeval *tv, bstr_t ptn);
	/**
	 * Find a pattern
	 */
	bptn_t (*ptn_find)(bstore_t bs, bptn_id_t ptn_id);
	/**
	 * Create/destroy a pattern iterator
	 */
	bstore_iter_pos_t (*ptn_iter_pos)(bptn_iter_t);
	int (*ptn_iter_pos_set)(bptn_iter_t, bstore_iter_pos_t);
	bptn_iter_t (*ptn_iter_new)(bstore_t bs);
	void (*ptn_iter_free)(bptn_iter_t i);
	uint64_t (*ptn_iter_card)(bptn_iter_t i);
	/**
	 * Return the first pattern
	 */
	bptn_t (*ptn_iter_find)(bptn_iter_t iter, time_t start);
	/**
	 * Advance to the next pattern.
	 */
	bptn_t (*ptn_iter_next)(bptn_iter_t iter);
	/**
	 * Advance to the prevous pattern.
	 */
	bptn_t (*ptn_iter_prev)(bptn_iter_t iter);
	/**
	 * Advance to the first pattern.
	 */
	bptn_t (*ptn_iter_first)(bptn_iter_t iter);
	/**
	 * Advance to the last pattern.
	 */
	bptn_t (*ptn_iter_last)(bptn_iter_t iter);
	/**
	 * Create a pattern token iterator
	 */
	bstore_iter_pos_t (*ptn_tkn_iter_pos)(bptn_tkn_iter_t);
	int (*ptn_tkn_iter_pos_set)(bptn_tkn_iter_t, bstore_iter_pos_t);
	bptn_tkn_iter_t (*ptn_tkn_iter_new)(bstore_t bs);
	void (*ptn_tkn_iter_free)(bptn_tkn_iter_t i);
	uint64_t (*ptn_tkn_iter_card)(bptn_tkn_iter_t i);
	/**
	 * Return the first token at the specified pattern position
	 */
	btkn_t (*ptn_tkn_iter_find)(bptn_tkn_iter_t iter, bptn_id_t ptn_id, uint64_t pos);
	/**
	 * Return the next pattern token
	 */
	btkn_t (*ptn_tkn_iter_next)(bptn_tkn_iter_t iter);
	/**
	 * Return the type id for a token type name
	 */
	btkn_type_t (*tkn_type_get)(bstore_t bs, const char *name, size_t name_len);

	/**
	 * Maintain the token histograms
	 */
	int (*tkn_hist_update)(bstore_t bs, time_t sec, time_t bin_width,
			       btkn_id_t tkn_id);
	bstore_iter_pos_t (*tkn_hist_iter_pos)(btkn_hist_iter_t);
	int (*tkn_hist_iter_pos_set)(btkn_hist_iter_t, bstore_iter_pos_t);
	btkn_hist_iter_t (*tkn_hist_iter_new)(bstore_t bs);
	void (*tkn_hist_iter_free)(btkn_hist_iter_t iter);
	btkn_hist_t (*tkn_hist_iter_find)(btkn_hist_iter_t iter, btkn_hist_t tkn_h);
	btkn_hist_t (*tkn_hist_iter_next)(btkn_hist_iter_t iter, btkn_hist_t tkn_h);
	btkn_hist_t (*tkn_hist_iter_first)(btkn_hist_iter_t iter, btkn_hist_t tkn_h);

	/**
	 * Maintain the pattern histograms
	 */
	int (*ptn_hist_update)(bstore_t bs,
			       bptn_id_t ptn_id, bcomp_id_t comp_id,
			       time_t secs, time_t bin_width);
	/**
	 * Record which tokens appeared at which position in the pattern
	 */
	int (*ptn_tkn_add)(bstore_t bs,
			   bptn_id_t ptn_id, uint64_t tkn_pos, btkn_id_t tkn_id);
	bstore_iter_pos_t (*ptn_hist_iter_pos)(bptn_hist_iter_t);
	int (*ptn_hist_iter_pos_set)(bptn_hist_iter_t, bstore_iter_pos_t);
	bptn_hist_iter_t (*ptn_hist_iter_new)(bstore_t bs);
	void (*ptn_hist_iter_free)(bptn_hist_iter_t iter);
	bptn_hist_t (*ptn_hist_iter_find)(bptn_hist_iter_t iter, bptn_hist_t ptn_h);
	bptn_hist_t (*ptn_hist_iter_next)(bptn_hist_iter_t iter, bptn_hist_t ptn_h);
	bptn_hist_t (*ptn_hist_iter_first)(bptn_hist_iter_t iter, bptn_hist_t ptn_h);

	bstore_iter_pos_t (*comp_hist_iter_pos)(bcomp_hist_iter_t);
	int (*comp_hist_iter_pos_set)(bcomp_hist_iter_t, bstore_iter_pos_t);
	bcomp_hist_iter_t (*comp_hist_iter_new)(bstore_t bs);
	void (*comp_hist_iter_free)(bcomp_hist_iter_t iter);
	bcomp_hist_t (*comp_hist_iter_find)(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);
	bcomp_hist_t (*comp_hist_iter_next)(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);
	bcomp_hist_t (*comp_hist_iter_first)(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);
	/**
	 * Iterator postion management routines
	 */
	const char *(*iter_pos_to_str)(bstore_iter_t, bstore_iter_pos_t);
	bstore_iter_pos_t (*iter_pos_from_str)(bstore_iter_t, const char *);
	void (*iter_pos_free)(bstore_iter_t, bstore_iter_pos_t);
} *bstore_plugin_t;

typedef bstore_plugin_t (*bstore_init_fn_t)(void);
bstore_t bstore_open(const char *plugin, const char *path, int flags, ...);
void bstore_close(bstore_t bs);
btkn_type_t bstore_tkn_get_type(bstore_t bs, const char *name, size_t name_len);
btkn_id_t bstore_tkn_add(bstore_t bs, btkn_t tkn);
int bstore_tkn_add_with_id(bstore_t bs, btkn_t tkn);

btkn_t bstore_tkn_find_by_id(bstore_t bs, btkn_id_t tkn_id);
btkn_t bstore_tkn_find_by_name(bstore_t bs, const char *name, size_t name_len);
bstore_iter_pos_t bstore_tkn_iter_pos(btkn_iter_t);
int bstore_tkn_iter_pos_set(btkn_iter_t, bstore_iter_pos_t);
btkn_iter_t bstore_tkn_iter_new(bstore_t bs);
void bstore_tkn_iter_free(btkn_iter_t i);
uint64_t bstore_tkn_iter_card(btkn_iter_t i);
btkn_t bstore_tkn_iter_first(btkn_iter_t iter);
btkn_t bstore_tkn_iter_next(btkn_iter_t iter);

int bstore_msg_add(bstore_t bs, struct timeval *tv, bmsg_t msg);
bstore_iter_pos_t bstore_msg_iter_pos(bmsg_iter_t);
int bstore_msg_iter_pos_set(bmsg_iter_t, bstore_iter_pos_t);
bmsg_iter_t bstore_msg_iter_new(bstore_t bs);
void bstore_msg_iter_free(bmsg_iter_t i);
uint64_t bstore_msg_iter_card(bmsg_iter_t i);
bmsg_t bstore_msg_iter_find(bmsg_iter_t i,
			    bptn_id_t ptn_id, time_t start, bcomp_id_t comp_id,
			    bmsg_cmp_fn_t cmp_fn, void *ctxt);
bmsg_t bstore_msg_iter_next(bmsg_iter_t i);
bmsg_t bstore_msg_iter_prev(bmsg_iter_t i);
bmsg_t bstore_msg_iter_first(bmsg_iter_t i);
bmsg_t bstore_msg_iter_last(bmsg_iter_t i);

bptn_id_t bstore_ptn_add(bstore_t bs, struct timeval *tv, bstr_t ptn);
bptn_t bstore_ptn_find(bstore_t bs, bptn_id_t ptn_id);
bstore_iter_pos_t bstore_ptn_iter_pos(bptn_iter_t);
int bstore_ptn_iter_pos_set(bptn_iter_t, bstore_iter_pos_t);
bptn_iter_t bstore_ptn_iter_new(bstore_t bs);
void bstore_ptn_iter_free(bptn_iter_t iter);
uint64_t bstore_ptn_iter_card(bptn_iter_t i);
bptn_t bstore_ptn_iter_find(bptn_iter_t iter, time_t start);
bptn_t bstore_ptn_iter_next(bptn_iter_t iter);
bptn_t bstore_ptn_iter_prev(bptn_iter_t iter);
bptn_t bstore_ptn_iter_first(bptn_iter_t iter);
bptn_t bstore_ptn_iter_last(bptn_iter_t iter);

bstore_iter_pos_t bstore_ptn_tkn_iter_pos(bptn_tkn_iter_t);
int bstore_ptn_tkn_iter_pos_set(bptn_tkn_iter_t, bstore_iter_pos_t);
bptn_tkn_iter_t bstore_ptn_tkn_iter_new(bstore_t bs);
void bstore_ptn_tkn_iter_free(bptn_tkn_iter_t iter);
uint64_t bstore_ptn_tkn_iter_card(bptn_tkn_iter_t i);
btkn_t bstore_ptn_tkn_iter_find(bptn_tkn_iter_t iter, bptn_id_t ptn_id, uint64_t pos);
btkn_t bstore_ptn_tkn_iter_next(bptn_tkn_iter_t iter);

/* Token History */
int bstore_tkn_hist_update(bstore_t bs, time_t secs, time_t bin_width, btkn_id_t tkn_id);
bstore_iter_pos_t bstore_tkn_hist_iter_pos(btkn_hist_iter_t);
int bstore_tkn_hist_iter_pos_set(btkn_hist_iter_t, bstore_iter_pos_t);
btkn_hist_iter_t bstore_tkn_hist_iter_new(bstore_t bs);
void bstore_tkn_hist_iter_free(btkn_hist_iter_t iter);
btkn_hist_t bstore_tkn_hist_iter_find(btkn_hist_iter_t iter, btkn_hist_t tkn_h);
btkn_hist_t bstore_tkn_hist_iter_next(btkn_hist_iter_t iter, btkn_hist_t tkn_h);
btkn_hist_t bstore_tkn_hist_iter_first(btkn_hist_iter_t iter, btkn_hist_t tkn_h);

/* Pattern History */
int bstore_ptn_hist_update(bstore_t bs, bptn_id_t ptn_id, bcomp_id_t comp_id,
			   time_t secs, time_t bin_width);
int bstore_ptn_tkn_add(bstore_t bs, bptn_id_t ptn_id, uint64_t tkn_pos, btkn_id_t tkn_id);
bstore_iter_pos_t bstore_ptn_hist_iter_pos(bptn_hist_iter_t);
int bstore_ptn_hist_iter_pos_set(bptn_hist_iter_t, bstore_iter_pos_t);
bptn_hist_iter_t bstore_ptn_hist_iter_new(bstore_t bs);
void bstore_ptn_hist_iter_free(bptn_hist_iter_t iter);
bptn_hist_t bstore_ptn_hist_iter_find(bptn_hist_iter_t iter, bptn_hist_t ptn_h);
bptn_hist_t bstore_ptn_hist_iter_next(bptn_hist_iter_t iter, bptn_hist_t ptn_h);
bptn_hist_t bstore_ptn_hist_iter_first(bptn_hist_iter_t iter, bptn_hist_t ptn_h);

/* Component History */
bstore_iter_pos_t bstore_comp_hist_iter_pos(bcomp_hist_iter_t);
int bstore_comp_hist_iter_pos_set(bcomp_hist_iter_t, bstore_iter_pos_t);
bcomp_hist_iter_t bstore_comp_hist_iter_new(bstore_t bs);
void bstore_comp_hist_iter_free(bcomp_hist_iter_t iter);
bcomp_hist_t bstore_comp_hist_iter_find(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);
bcomp_hist_t bstore_comp_hist_iter_next(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);
bcomp_hist_t bstore_comp_hist_iter_first(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);

/* Iterator position management routines */
const char *bstore_iter_pos_to_str(bstore_iter_t iter, bstore_iter_pos_t pos);
bstore_iter_pos_t bstore_iter_pos_from_str(bstore_iter_t iter, const char *pos);
void bstore_iter_pos_free(bstore_iter_t iter, bstore_iter_pos_t pos);

#endif
