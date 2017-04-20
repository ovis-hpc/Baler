/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2016 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2016 Sandia Corporation. All rights reserved.
 * Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 * license for use of this work by or on behalf of the U.S. Government.
 * Export of this program may require a license from the United States
 * Government.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of Sandia nor the names of any contributors may
 *      be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 *      Neither the name of Open Grid Computing nor the names of any
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *      Modified source versions must be plainly marked as such, and
 *      must not be misrepresented as being the original software.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * \file bstore_agg.c
 * \author Narate Taerat (narate at ogc dot us)
 * \brief Read-only aggregation store.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>
#include <assert.h>
#include <ctype.h>
#include <unistd.h>
#include "sos/sos.h"
#include "coll/rbt.h"

#include "../baler/butils.h"
#include "../baler/bstore.h"
#include "../baler/bheap.h"

/*
 * NOTE: Please see documentation at the end of this file.
 */

#define MAX_UPDATERS 256
#define BPTN_ID_BEGIN 256

#ifndef __be64
#define __be64
#endif
#ifndef __be32
#define __be32
#endif

typedef struct bstore_entry_s {
	struct bstore_s *bs;
	TAILQ_ENTRY(bstore_entry_s) link; /* list in bsa */
	TAILQ_ENTRY(bstore_entry_s) updater_link; /* list in updater */
} *bstore_entry_t;

typedef TAILQ_HEAD(bstore_head_s, bstore_entry_s) *bstore_head_t;

#pragma pack(4)
typedef struct bsa_shmem {
	union {
		struct {
			uint64_t next_tkn_id;
			uint64_t next_ptn_id;
			struct timeval last_update_end;
			struct timeval last_update_begin;
		};
		char _hdr_space_[4096];
	};
} *bsa_shmem_t;
#pragma pack() /* restore pack parameter */

typedef struct bsa_s *bsa_t;
#define BSA(bs) ((bsa_t)bs)
typedef struct bsa_updater_s *bsa_updater_t;

struct bsa_updater_s {
	bsa_t bsa;
	pthread_t thread;
	struct bstore_head_s bs_tq; /* bstore tailq */
	int init_state;
	/* init_state:
	 *   0: no additional resources allocated yet
	 *   1: thread allocated
	 */
};

#pragma pack(4)
struct ptn_pos_tkn_s {
	union {
		struct {
			__be64 uint64_t ptn_id;
			__be64 uint64_t pos;
			__be64 uint64_t tkn_id;
		};
		char key[0];
	};
};
#pragma pop()
typedef struct ptn_pos_tkn_s *ptn_pos_tkn_t;

struct bsa_s {
	struct bstore_s base;
	/* extend the structure here */
	uint32_t ref_count; /* reference count */
	sos_t tkn_sos; /* sos for tokens */
	sos_t ptn_sos; /* sos for patterns */
	sos_t ptn_pos_tkn_sos; /* sos for patterns */
	struct bstore_head_s bs_tq; /* list of sub-store */
	int bs_n; /* number of sub-store */
	int o_mode;

	int shmem_fd; /* file descriptor for the shared memory */
	bsa_shmem_t shmem; /* shared memory region */

	sos_schema_t token_value_schema;
	sos_schema_t pattern_schema;
	sos_schema_t pattern_token_schema;

	sos_attr_t tkn_id_attr; /* Token.tkn_id */
	sos_attr_t tkn_type_mask_attr; /* Token.tkn_type_mask */
	sos_attr_t tkn_text_attr; /* Token.tkn_text */

	sos_attr_t ptn_id_attr;	  /* Pattern.ptn_id */
	sos_attr_t ptn_first_seen_attr;	  /* Pattern.first_seen */
	sos_attr_t ptn_type_ids_attr; /* Pattern.tkn_type_ids */
			      /* NOTE: type_ids = [8-bit type|54-bit id] */

	sos_attr_t ptn_pos_tkn_key_attr;

	/* updater section */
	struct timeval update_interval; /* update interval in seconds */
	pthread_cond_t update_cond; /* update condition */
	pthread_mutex_t update_mutex; /* mutex for update_cond */
	int update_need; /* update_need (use with update_cond) */
	int n_updaters; /* number of updaters */
	struct bsa_updater_s updater[MAX_UPDATERS];

	char store_path[PATH_MAX]; /* store: path */
	char buff[PATH_MAX]; /* path construction buffer */
};

typedef enum {
	BSA_ITER_TYPE_FIRST,
	BSA_ITER_TYPE_PTN_ID,
	BSA_ITER_TYPE_PTN_FIRST_SEEN,
	BSA_ITER_TYPE_TKN,
	BSA_ITER_TYPE_MSG,
	BSA_ITER_TYPE_PTN_TKN,
	BSA_ITER_TYPE_TKN_HIST,
	BSA_ITER_TYPE_PTN_HIST,
	BSA_ITER_TYPE_COMP_HIST,
	BSA_ITER_TYPE_LAST,
} bsa_iter_type_t;

typedef struct bsa_ptn_iter_s {
	struct bstore_iter_s base;
	bsa_iter_type_t type; /* for PTN_ID or PTN_FIRST_SEEN */
	sos_iter_t sitr;
	bptn_id_t ptn_id;
} *bsa_ptn_iter_t;

typedef struct bsa_ptn_tkn_iter_s {
	struct bstore_iter_s base;
	struct ptn_pos_tkn_s kv;
	sos_iter_t sitr;
} *bsa_ptn_tkn_iter_t;

typedef struct bsa_tkn_iter_s {
	struct bstore_iter_s base;
	sos_iter_t sitr;
} *bsa_tkn_iter_t;

typedef struct bsa_msg_iter_s {
	struct bstore_iter_s base;
	struct bheap *heap; /* heap of bsa_msg_iter_heap_ent_t */
} *bsa_msg_iter_t;

#define BSA_TKN_ITER(i) ((bsa_tkn_iter_t)i)

typedef struct bsa_iter_pos_s {
	struct bstore_iter_pos_s bs_pos;
	bsa_iter_type_t type;
} *bsa_iter_pos_t;

static inline bstore_iter_pos_t BS_POS(void *x)
{
	return x;
}

static inline bsa_iter_pos_t BSA_POS(void *x)
{
	return x;
}

typedef struct bsa_tkn_iter_pos_s {
	struct bsa_iter_pos_s bsa_pos;
	struct sos_pos sos_pos;
} *bsa_tkn_iter_pos_t;

typedef struct bsa_ptn_iter_pos_s {
	struct bsa_iter_pos_s bsa_pos;
	union {
		bptn_id_t ptn_id; /* ptn_id is the position */
		struct sos_pos sos_pos; /* sos position */
	};
} *bsa_ptn_iter_pos_t;

typedef struct bsa_ptn_tkn_iter_pos_s {
	struct bsa_iter_pos_s bs_pos;
	struct sos_pos sos_pos;
} *bsa_ptn_tkn_iter_pos_t;

struct __visit_ctxt {
	bsa_t bsa;
	int add;
	btkn_t tkn;
	bptn_t ptn;
	ptn_pos_tkn_t ptn_pos_tkn;
};

typedef struct bsa_heap_iter_entry_s {
	bstore_iter_t itr;
	TAILQ_ENTRY(bsa_heap_iter_entry_s) link;
	void *obj;
	char data[0];
} *bsa_heap_iter_entry_t;

typedef enum {
	BSA_DIRECTION_FWD,
	BSA_DIRECTION_BWD,
} bsa_direction_t; /* direction */
/*
 * bsa_heap_iter is an iterator of a heap of iterators.
 */
typedef struct bsa_heap_iter_s *bsa_heap_iter_t;
struct bsa_heap_iter_s {
	struct bstore_iter_s base;
	bsa_iter_type_t type; /* type of iterators in the heap */

	/*
	 * This is a linked-list of heap entries with the same order
	 * as sub-bstore (bs_tq) in `struct bsa_s`.
	 */
	TAILQ_HEAD(, bsa_heap_iter_entry_s) hent_tq;

	/*
	 * This heap contain pointers to heap entries in hent_tq.
	 */
	struct bheap *heap;

	bsa_direction_t dir;

	/* Pointers to functions of iterators in the heap */
	void *(*iter_new)(bstore_t bs);
	void (*iter_free)(void *itr);
	uint64_t (*iter_card)(void *itr);

	/* return object is newly allocated */
	union {
		void *(*iter_first)(void *itr);
		void *(*iter_first_r)(void *itr, void *arg);
	};
	union {
		void *(*iter_next)(void *itr);
		void *(*iter_next_r)(void *itr, void *arg);
	};
	union {
		void *(*iter_prev)(void *itr);
		void *(*iter_prev_r)(void *itr, void *arg);
	};
	union {
		void *(*iter_last)(void *itr);
		void *(*iter_last_r)(void *itr, void *arg);
	};
	union {
		void *(*iter_obj)(void *itr);
		void *(*iter_obj_r)(void *itr, void *arg);
	};

	bstore_iter_pos_t (*iter_pos)(bstore_iter_t itr);
	int (*iter_pos_set)(bstore_iter_t itr, bstore_iter_pos_t pos);

	void *(*obj_dup)(void *obj);
	void *(*obj_copy)(void*, void*);
	uint32_t (*obj_time)(void*);
	void (*obj_free)(void *obj);

	int (*hent_fwd_cmp)(bsa_heap_iter_entry_t, bsa_heap_iter_entry_t);
	int (*hent_bwd_cmp)(bsa_heap_iter_entry_t, bsa_heap_iter_entry_t);

	/* xlate from bs -> bsa namespace */
	int (*hent_xlate)(bsa_heap_iter_t, bsa_heap_iter_entry_t);

	/* xlate from bsa -> bs namespace */
	int (*hent_rev_xlate)(bsa_heap_iter_t, bsa_heap_iter_entry_t);
};

typedef struct bsa_heap_iter_pos_s {
	struct bsa_iter_pos_s bsa_pos;
	bsa_direction_t dir;
	int n;
	struct bstore_iter_pos_s bs_pos[0];
} *bsa_heap_iter_pos_t;

union bsa_hist_u {
	struct btkn_hist_s tkn_hist;
	struct bptn_hist_s ptn_hist;
	struct bcomp_hist_s comp_hist;
	char data[0];
};

typedef struct bsa_hist_s {
	struct rbn rbn;
	TAILQ_ENTRY(bsa_hist_s) link;
	union bsa_hist_u u;
} *bsa_hist_t;

#define BSA_HIST_RBN(x) ((bsa_hist_t)x)

typedef struct bsa_hist_iter_s *bsa_hist_iter_t;
struct bsa_hist_iter_s {
	struct bstore_iter_s base;
	struct rbt rbt;
	TAILQ_HEAD(, bsa_hist_s) head;
	bsa_hist_t curr; /* current hist in the buffer tree */
	struct bsa_hist_s bsa_hist;
	bsa_heap_iter_t hitr;
	bsa_heap_iter_pos_t hitr_pos; /* heap iter pos BEFORE buffer replenish */
	union bsa_hist_u hitr_hist; /* hist BEFORE buffer replenish */
	int (*hist_key_cmp)(void *a, void *b);
	void (*hist_merge)(void *a, void *b);
	union bsa_hist_u *hobj; /* current object, which can only be NULL or
				  &bsa_hist.data */
};

typedef struct bsa_hist_iter_pos_s {
	struct bsa_iter_pos_s base;
	bsa_direction_t dir;
	union bsa_hist_u curr; /* to recover current rbn */
	union bsa_hist_u hitr_hist; /* to recover hobj BEFORE replenish */
	struct bstore_iter_pos_s hitr_pos; /* position BEFORE replenish */
} *bsa_hist_iter_pos_t;


/*========================*/
/* SOS related structures */
/*========================*/

typedef struct tkn_value_s {
	uint64_t tkn_id;
	uint64_t tkn_type_mask;
	uint64_t tkn_count;
	union sos_obj_ref_s tkn_text;
} *tkn_value_t;

#define H2BXT_IDX_ARGS "ORDER=5 SIZE=3"

struct sos_schema_template token_value_schema = {
	.name = "TokenValue",
	.attrs = {
		{
			.name = "tkn_id",
			.type = SOS_TYPE_UINT64,
			.indexed = 1,
			.idx_type = "HTBL",
		},
		{ /* one bit for each type seen for this text (0..63)*/
			.name = "tkn_type_mask",
			.type = SOS_TYPE_UINT64,
		},
		{
			.name = "tkn_count",
			.type = SOS_TYPE_UINT64,
		},
		{
			.name = "tkn_text",
			.type = SOS_TYPE_CHAR_ARRAY,
			.indexed = 1,
			.idx_type = "HTBL",
		},
		{ NULL }
	}
};

typedef struct sptn_value_s {
	uint64_t ptn_id;
	struct sos_timestamp_s first_seen;
	struct sos_timestamp_s last_seen;
	uint64_t count;
	uint64_t tkn_count;
	union sos_obj_ref_s tkn_type_ids;
} *sptn_value_t;

struct sos_schema_template pattern_schema = {
	.name = "Pattern",
	.attrs = {
		{
			.name = "ptn_id",
			.type = SOS_TYPE_UINT64,
			.indexed = 1,
			.idx_type = "HTBL",
		},
		{
			.name = "first_seen",
			.type = SOS_TYPE_TIMESTAMP,
			.indexed = 1,
		},
		{
			.name = "last_seen",
			.type = SOS_TYPE_TIMESTAMP,
		},
		{
			.name = "count",
			.type = SOS_TYPE_UINT64,
		},
		{
			.name = "tkn_count",
			.type = SOS_TYPE_UINT64,
		},
		{
			.name = "tkn_type_ids",
			.type = SOS_TYPE_BYTE_ARRAY,
			.indexed = 1,
			.idx_type = "HTBL",
		},
		{ NULL }
	}
};

struct sos_schema_template pattern_token_schema = {
	.name = "PatternToken",
	.attrs = {
		{
			.name = "ptn_pos_tkn_key",
			.type = SOS_TYPE_STRUCT,
			.indexed = 1,
			.idx_type = "BXTREE",
			.idx_args = "ORDER=5 SIZE=7",
			.size = 24,
			.key_type = "MEMCMP",
		},
		{ NULL }
	}
};

/*========================================*/
/*===== internal function prototypes =====*/
/*========================================*/
static int __bsa_tkn_add(bsa_t bsa, btkn_t tkn);
static int __bsa_ptn_find(bsa_t bsa, bptn_t ptn, int add);
static int __bsa_shmem_open(bsa_t bsa);

void *bsa_heap_iter_next(bsa_heap_iter_t itr, void *buff);
void *bsa_heap_iter_prev(bsa_heap_iter_t itr, void *buff);

static int bsa_heap_iter_entry_msg_fwd_cmp(bsa_heap_iter_entry_t a,
					   bsa_heap_iter_entry_t b);
static int bsa_heap_iter_entry_msg_bwd_cmp(bsa_heap_iter_entry_t a,
					   bsa_heap_iter_entry_t b);

static int bsa_heap_iter_entry_tkn_hist_fwd_cmp(bsa_heap_iter_entry_t a,
						bsa_heap_iter_entry_t b);
static int bsa_heap_iter_entry_tkn_hist_bwd_cmp(bsa_heap_iter_entry_t a,
						bsa_heap_iter_entry_t b);

static int bsa_heap_iter_entry_ptn_hist_fwd_cmp(bsa_heap_iter_entry_t a,
						bsa_heap_iter_entry_t b);
static int bsa_heap_iter_entry_ptn_hist_bwd_cmp(bsa_heap_iter_entry_t a,
						bsa_heap_iter_entry_t b);

static int bsa_heap_iter_entry_comp_hist_fwd_cmp(bsa_heap_iter_entry_t a,
						bsa_heap_iter_entry_t b);
static int bsa_heap_iter_entry_comp_hist_bwd_cmp(bsa_heap_iter_entry_t a,
						bsa_heap_iter_entry_t b);

void bsa_heap_iter_entry_reset(bsa_heap_iter_t itr, bsa_heap_iter_entry_t hent);

int bsa_tkn_hist_fwd_key_cmp(const struct btkn_hist_s *a,
			     const struct btkn_hist_s *b);
int bsa_tkn_hist_bwd_key_cmp(const struct btkn_hist_s *a,
			     const struct btkn_hist_s *b);
void bsa_tkn_hist_merge(btkn_hist_t a, btkn_hist_t b);
btkn_hist_t bsa_tkn_hist_copy(btkn_hist_t a, btkn_hist_t b);
uint32_t bsa_tkn_hist_time(btkn_hist_t a);

int bsa_ptn_hist_fwd_key_cmp(const struct bptn_hist_s *a,
			     const struct bptn_hist_s *b);
int bsa_ptn_hist_bwd_key_cmp(const struct bptn_hist_s *a,
			     const struct bptn_hist_s *b);
void bsa_ptn_hist_merge(bptn_hist_t a, bptn_hist_t b);
bptn_hist_t bsa_ptn_hist_copy(bptn_hist_t a, bptn_hist_t b);
uint32_t bsa_ptn_hist_time(bptn_hist_t a);

int bsa_comp_hist_fwd_key_cmp(const struct bcomp_hist_s *a,
			      const struct bcomp_hist_s *b);
int bsa_comp_hist_bwd_key_cmp(const struct bcomp_hist_s *a,
			      const struct bcomp_hist_s *b);
void bsa_comp_hist_merge(bcomp_hist_t a, bcomp_hist_t b);
bcomp_hist_t bsa_comp_hist_copy(bcomp_hist_t a, bcomp_hist_t b);
uint32_t bsa_comp_hist_time(bcomp_hist_t a);

static
bptn_t bsa_ptn_find(bstore_t bs, bptn_id_t ptn_id);
static
btkn_t bsa_ptn_tkn_find(bstore_t bs,
		       bptn_id_t ptn_id, uint64_t tkn_pos, btkn_id_t tkn_id);
static
btkn_t bsa_ptn_tkn_iter_obj(bptn_tkn_iter_t _itr);

/*
 * Translate token + pattern from `bs` id space into `bsa` id space.
 */
static inline int __bsa_tkn_xlate(bsa_t bsa, bstore_t bs, btkn_t tkn);
static int __bsa_ptn_xlate(bsa_t bsa, bstore_t bs, bptn_t ptn);

/*
 * Translate `ptn_from` pattern in `bs_from` space into `bs_to` space. The input
 * `ptn_from` pattern won't be modified. Instead, the function returns bptn the
 * newly created translated pattern.
 *
 * NOTE: __ptn_xlate() doesn't set ptn_id in the returned ptn.
 */
static bptn_t __ptn_xlate(bptn_t ptn_from, bstore_t bs_from, bstore_t bs_to);

static btkn_id_t __tkn_id_xlate(btkn_id_t id_from,
				bstore_t bs_from, bstore_t bs_to);
static inline bcomp_id_t __comp_id_xlate(bcomp_id_t id_from,
				bstore_t bs_from, bstore_t bs_to);
static bptn_id_t __ptn_id_xlate(bptn_id_t id_from,
				bstore_t bs_from, bstore_t bs_to);

static void bsa_close(bstore_t bs);

struct __attr_entry_s {
	sos_attr_t *_attr_out;
	const char *name;
};

int bsa_heap_iter_hent_msg_xlate(bsa_heap_iter_t itr, bsa_heap_iter_entry_t hent)
{
	int rc = 0;
	int i;
	bptn_t ptn;
	btkn_t tkn;
	bsa_t bsa = (void*)itr->base.bs;
	bstore_t bs = hent->itr->bs;
	bmsg_t msg = hent->obj;

	ptn = bstore_ptn_find(bs, msg->ptn_id);
	rc = __bsa_ptn_xlate(bsa, bs, ptn);
	msg->ptn_id = ptn->ptn_id;
	bptn_free(ptn);
	tkn = bstore_tkn_find_by_id(bs, msg->comp_id);
	assert(tkn);
	tkn->tkn_id = 0;
	rc = __bsa_tkn_xlate(bsa, bs, tkn);
	assert(rc == 0);
	msg->comp_id = tkn->tkn_id;
	btkn_free(tkn);
	for (i = 0; i < msg->argc; i++) {
		uint64_t tkn_data = msg->argv[i];
		btkn_id_t tkn_id = tkn_data >> 8;
		btkn_type_t type = tkn_data & 0xFF;
		tkn = bstore_tkn_find_by_id(bs, tkn_id);
		if (!tkn) {
			rc = errno;
			goto out;
		}
		rc = __bsa_tkn_xlate(bsa, bs, tkn);
		if (rc) {
			btkn_free(tkn);
			goto out;
		}
		assert(0 == (tkn->tkn_id >> 56));
		msg->argv[i] = (tkn->tkn_id<<8) | type;
		btkn_free(tkn);
	}
out:
	return rc;
}

int bsa_heap_iter_hent_tkn_hist_xlate(bsa_heap_iter_t itr,
					bsa_heap_iter_entry_t hent)
{
	btkn_hist_t hist = (void*)hent->data;
	if (!hist->tkn_id) /* no need for translation */
		return 0;
	/* hist should be in host-endian format */
	/* translate only the token ID */
	hist->tkn_id = __tkn_id_xlate(hist->tkn_id, hent->itr->bs, itr->base.bs);
	if (hist->tkn_id)
		return 0;
	return errno;
}

int bsa_heap_iter_hent_tkn_hist_rev_xlate(bsa_heap_iter_t itr,
					bsa_heap_iter_entry_t hent)
{
	btkn_hist_t hist = (void*)hent->data;
	if (!hist->tkn_id) /* no need for translation */
		return 0;
	/* hist should be in host-endian format */
	/* translate only the token ID */
	hist->tkn_id = __tkn_id_xlate(hist->tkn_id, itr->base.bs, hent->itr->bs);
	if (hist->tkn_id)
		return 0;
	return errno;
}

int bsa_heap_iter_hent_ptn_hist_xlate(bsa_heap_iter_t itr,
				      bsa_heap_iter_entry_t hent)
{
	bptn_hist_t hist = (void*)hent->data;
	if (!hist->ptn_id) /* translation not needed */
		return 0;
	hist->ptn_id = __ptn_id_xlate(hist->ptn_id, hent->itr->bs, itr->base.bs);
	if (hist->ptn_id)
		return 0;
	return errno;
}

int bsa_heap_iter_hent_ptn_hist_rev_xlate(bsa_heap_iter_t itr,
					  bsa_heap_iter_entry_t hent)
{
	bptn_hist_t hist = (void*)hent->data;
	if (!hist->ptn_id) /* translation not needed */
		return 0;
	hist->ptn_id = __ptn_id_xlate(hist->ptn_id, itr->base.bs, hent->itr->bs);
	if (hist->ptn_id)
		return 0;
	return errno;
}

int bsa_heap_iter_hent_comp_hist_xlate(bsa_heap_iter_t itr,
				      bsa_heap_iter_entry_t hent)
{
	bcomp_hist_t hist = (void*)hent->data;

ptn_id:
	if (!hist->ptn_id)
		goto comp_id;
	hist->ptn_id = __ptn_id_xlate(hist->ptn_id, hent->itr->bs,
					itr->base.bs);
	if (!hist->ptn_id)
		return errno;

comp_id:
	if (!hist->comp_id)
		goto out;
	hist->comp_id = __comp_id_xlate(hist->comp_id, hent->itr->bs,
					itr->base.bs);
	if (!hist->comp_id)
		return errno;

out:
	return 0;
}

int bsa_heap_iter_hent_comp_hist_rev_xlate(bsa_heap_iter_t itr,
				      bsa_heap_iter_entry_t hent)
{
	bcomp_hist_t hist = (void*)hent->data;

ptn_id:
	if (!hist->ptn_id)
		goto comp_id;
	hist->ptn_id = __ptn_id_xlate(hist->ptn_id, itr->base.bs,
					hent->itr->bs);
	if (!hist->ptn_id)
		return errno;

comp_id:
	if (!hist->comp_id)
		goto out;
	hist->comp_id = __comp_id_xlate(hist->comp_id, itr->base.bs,
					hent->itr->bs);
	if (!hist->comp_id)
		return errno;

out:
	return 0;
}

static void bsa_heap_iter_free(bsa_heap_iter_t itr);

btkn_hist_t __hist_iter_inval_op(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	errno = EINVAL;
	return NULL;
}

static
bsa_heap_iter_t bsa_heap_iter_new(bsa_t bsa, bsa_iter_type_t type)
{
	bsa_heap_iter_entry_t hent;
	bstore_entry_t bent;
	size_t hent_sz;
	bsa_heap_iter_t itr;
	int rc;

	itr = calloc(1, sizeof(*itr));
	if (!itr)
		goto err0;

	itr->type = type;
	itr->base.bs = (void*)bsa;
	switch (type) {
	case BSA_ITER_TYPE_MSG:
		itr->iter_first = (void*)bstore_msg_iter_first;
		itr->iter_next = (void*)bstore_msg_iter_next;
		itr->iter_prev = (void*)bstore_msg_iter_prev;
		itr->iter_last = (void*)bstore_msg_iter_last;
		itr->iter_obj = (void*)bstore_msg_iter_obj;
		itr->iter_new = (void*)bstore_msg_iter_new;
		itr->iter_free = (void*)bstore_msg_iter_free;
		itr->iter_card = (void*)bstore_msg_iter_card;
		itr->obj_free = free;
		itr->obj_dup = (void*)bmsg_dup;
		itr->hent_xlate = bsa_heap_iter_hent_msg_xlate;
		itr->iter_pos = bstore_msg_iter_pos;
		itr->iter_pos_set = bstore_msg_iter_pos_set;
		itr->hent_fwd_cmp = bsa_heap_iter_entry_msg_fwd_cmp;
		itr->hent_bwd_cmp = bsa_heap_iter_entry_msg_bwd_cmp;
		hent_sz = sizeof(*hent); /* no need for buffer */
		break;
	case BSA_ITER_TYPE_TKN_HIST:
		itr->iter_first_r = (void*)bstore_tkn_hist_iter_first;
		itr->iter_next_r = (void*)bstore_tkn_hist_iter_next;
		itr->iter_prev_r = (void*)__hist_iter_inval_op;
		itr->iter_last_r = (void*)bstore_tkn_hist_iter_last;
		itr->iter_obj_r = (void*)bstore_tkn_hist_iter_obj;
		itr->iter_new = (void*)bstore_tkn_hist_iter_new;
		itr->iter_free = (void*)bstore_tkn_hist_iter_free;
		/* no obj_free() and obj_dup() */
		itr->obj_copy = (void*)bsa_tkn_hist_copy;
		itr->obj_time = (void*)bsa_tkn_hist_time;
		itr->hent_xlate = bsa_heap_iter_hent_tkn_hist_xlate;
		itr->hent_rev_xlate = bsa_heap_iter_hent_tkn_hist_rev_xlate;
		itr->iter_pos = bstore_tkn_hist_iter_pos;
		itr->iter_pos_set = bstore_tkn_hist_iter_pos_set;
		itr->hent_fwd_cmp = bsa_heap_iter_entry_tkn_hist_fwd_cmp;
		itr->hent_bwd_cmp = bsa_heap_iter_entry_tkn_hist_bwd_cmp;
		hent_sz = sizeof(*hent) + sizeof(struct btkn_hist_s);
		break;
	case BSA_ITER_TYPE_PTN_HIST:
		itr->iter_first_r = (void*)bstore_ptn_hist_iter_first;
		itr->iter_next_r = (void*)bstore_ptn_hist_iter_next;
		itr->iter_prev_r = (void*)__hist_iter_inval_op;
		itr->iter_last_r = (void*)bstore_ptn_hist_iter_last;
		itr->iter_obj_r = (void*)bstore_ptn_hist_iter_obj;
		itr->iter_new = (void*)bstore_ptn_hist_iter_new;
		itr->iter_free = (void*)bstore_ptn_hist_iter_free;

		itr->obj_copy = (void*)bsa_ptn_hist_copy;
		itr->obj_time = (void*)bsa_ptn_hist_time;
		itr->hent_xlate = bsa_heap_iter_hent_ptn_hist_xlate;
		itr->hent_rev_xlate = bsa_heap_iter_hent_ptn_hist_rev_xlate;
		itr->iter_pos = bstore_ptn_hist_iter_pos;
		itr->iter_pos_set = bstore_ptn_hist_iter_pos_set;
		itr->hent_fwd_cmp = bsa_heap_iter_entry_ptn_hist_fwd_cmp;
		itr->hent_bwd_cmp = bsa_heap_iter_entry_ptn_hist_bwd_cmp;
		hent_sz = sizeof(*hent) + sizeof(struct bptn_hist_s);
		break;
	case BSA_ITER_TYPE_COMP_HIST:
		itr->iter_first_r = (void*)bstore_comp_hist_iter_first;
		itr->iter_next_r = (void*)bstore_comp_hist_iter_next;
		itr->iter_prev_r = (void*)__hist_iter_inval_op;
		itr->iter_last_r = (void*)bstore_comp_hist_iter_last;
		itr->iter_obj_r = (void*)bstore_comp_hist_iter_obj;
		itr->iter_new = (void*)bstore_comp_hist_iter_new;
		itr->iter_free = (void*)bstore_comp_hist_iter_free;

		itr->obj_copy = (void*)bsa_comp_hist_copy;
		itr->obj_time = (void*)bsa_comp_hist_time;
		itr->hent_xlate = bsa_heap_iter_hent_comp_hist_xlate;
		itr->hent_rev_xlate = bsa_heap_iter_hent_comp_hist_rev_xlate;
		itr->iter_pos = bstore_comp_hist_iter_pos;
		itr->iter_pos_set = bstore_comp_hist_iter_pos_set;
		itr->hent_fwd_cmp = bsa_heap_iter_entry_comp_hist_fwd_cmp;
		itr->hent_bwd_cmp = bsa_heap_iter_entry_comp_hist_bwd_cmp;
		hent_sz = sizeof(*hent) + sizeof(struct bcomp_hist_s);
		break;
	default:
		assert(0);
	}

	TAILQ_INIT(&itr->hent_tq);

	itr->heap = bheap_new(1024, (void*)itr->hent_fwd_cmp);
	if (!itr->heap)
		goto err1;

	TAILQ_FOREACH(bent, &bsa->bs_tq, link) {
		hent = calloc(1, hent_sz);
		if (!hent)
			goto err1;
		TAILQ_INSERT_TAIL(&itr->hent_tq, hent, link);
		hent->itr = itr->iter_new(bent->bs);
		if (!hent->itr)
			goto err1;
		rc = bheap_insert(itr->heap, hent);
		if (rc)
			goto err1;
		continue;
	}
	return itr;

err1:
	bsa_heap_iter_free(itr);
err0:
	return NULL;
}

static
void bsa_heap_iter_free(bsa_heap_iter_t itr)
{
	bsa_heap_iter_entry_t hent;
	while ((hent = TAILQ_FIRST(&itr->hent_tq))) {
		TAILQ_REMOVE(&itr->hent_tq, hent, link);
		if (hent->obj && itr->obj_free)
			itr->obj_free(hent->obj);
		if (hent->itr)
			itr->iter_free(hent->itr);
		free(hent);
	}
	if (itr->heap)
		bheap_free(itr->heap);
	free(itr);
}

void *bsa_heap_iter_obj(bsa_heap_iter_t itr, void *buff)
{
	bsa_heap_iter_entry_t hent = bheap_get_top(itr->heap);
	if (!hent->obj)
		return NULL;
	if (buff) {
		/* use obj_copy */
		return itr->obj_copy(hent->obj, buff);
	}
	return itr->obj_dup(hent->obj);
}

uint64_t bsa_heap_iter_card(bsa_heap_iter_t itr)
{
	uint64_t sum = 0;
	bsa_heap_iter_entry_t hent;
	BHEAP_FOREACH(hent, itr->heap) {
		sum += itr->iter_card(hent->itr);
	}
	return sum;
}

static
int __bsa_heap_iter_entry_op(bsa_heap_iter_t itr, bsa_heap_iter_entry_t hent,
			       void *(*op)(void*))
{
	int rc = 0;
	if (itr->obj_free) {
		if (hent->obj)
			itr->obj_free(hent->obj);
		hent->obj = op(hent->itr);
	} else {
		/* no obj_free ... use the re-entrant version */
		hent->obj = ((void *(*)(void*,void*))op)(hent->itr, hent->data);
	}
	if (hent->obj && itr->hent_xlate) {
		rc = itr->hent_xlate(itr, hent);
	}
	return rc;
}

static inline
int bsa_heap_iter_entry_first(bsa_heap_iter_t itr, bsa_heap_iter_entry_t hent)
{
	return __bsa_heap_iter_entry_op(itr, hent, itr->iter_first);
}

static inline
int bsa_heap_iter_entry_next(bsa_heap_iter_t itr, bsa_heap_iter_entry_t hent)
{
	return __bsa_heap_iter_entry_op(itr, hent, itr->iter_next);
}

static inline
int bsa_heap_iter_entry_prev(bsa_heap_iter_t itr, bsa_heap_iter_entry_t hent)
{
	return __bsa_heap_iter_entry_op(itr, hent, itr->iter_prev);
}

static inline
int bsa_heap_iter_entry_last(bsa_heap_iter_t itr, bsa_heap_iter_entry_t hent)
{
	return __bsa_heap_iter_entry_op(itr, hent, itr->iter_last);
}

void *bsa_heap_iter_first(bsa_heap_iter_t itr, void *buff)
{
	int rc;
	bsa_heap_iter_entry_t hent;
	BHEAP_FOREACH(hent, itr->heap) {
		if (buff) {
			itr->obj_copy(buff, hent->data);
			rc = itr->hent_rev_xlate(itr, hent);
			if (rc)
				bsa_heap_iter_entry_reset(itr, hent);
			else
				bsa_heap_iter_entry_first(itr, hent);
		} else {
			bsa_heap_iter_entry_first(itr, hent);
		}
	}
	itr->dir = BSA_DIRECTION_FWD;
	bheap_set_cmp(itr->heap, (void*)itr->hent_fwd_cmp);
	return bsa_heap_iter_obj(itr, buff);
}

void *bsa_heap_iter_last(bsa_heap_iter_t itr, void *buff)
{
	int rc;
	bsa_heap_iter_entry_t hent;
	BHEAP_FOREACH(hent, itr->heap) {
		if (buff) {
			itr->obj_copy(buff, hent->data);
			rc = itr->hent_rev_xlate(itr, hent);
			if (rc)
				bsa_heap_iter_entry_reset(itr, hent);
			else
				bsa_heap_iter_entry_last(itr, hent);
		} else {
			bsa_heap_iter_entry_last(itr, hent);
		}
	}
	itr->dir = BSA_DIRECTION_BWD;
	bheap_set_cmp(itr->heap, (void*)itr->hent_bwd_cmp);
	return bsa_heap_iter_obj(itr, buff);
}

void *bsa_heap_iter_next(bsa_heap_iter_t itr, void *buff)
{
	bsa_heap_iter_entry_t hent;

	if (itr->dir != BSA_DIRECTION_FWD) {
		/* switch direction, need to apply direction switching on all
		 * iterators*/
		assert(itr->dir == BSA_DIRECTION_BWD);
		BHEAP_FOREACH(hent, itr->heap) {
			bsa_heap_iter_entry_next(itr, hent);
		}
		itr->dir = BSA_DIRECTION_FWD;
		bheap_set_cmp(itr->heap, (void*)itr->hent_fwd_cmp);
		goto out;
	}

	/* same direction, just step top iterator + percolate */
	hent = bheap_get_top(itr->heap);
	if (!hent || !hent->obj)
		return NULL;
	bsa_heap_iter_entry_next(itr, hent);
	bheap_percolate_top(itr->heap);
out:
	return bsa_heap_iter_obj(itr, buff);
}

void *bsa_heap_iter_prev(bsa_heap_iter_t itr, void *buff)
{
	bsa_heap_iter_entry_t hent;

	if (itr->dir != BSA_DIRECTION_BWD) {
		/* switch direction, need to apply direction switching on all
		 * iterators*/
		assert(itr->dir == BSA_DIRECTION_FWD);
		BHEAP_FOREACH(hent, itr->heap) {
			bsa_heap_iter_entry_prev(itr, hent);
		}
		itr->dir = BSA_DIRECTION_BWD;
		bheap_set_cmp(itr->heap, (void*)itr->hent_bwd_cmp);
		goto out;
	}

	/* same direction, just step top iterator + percolate */
	hent = bheap_get_top(itr->heap);
	if (!hent || !hent->obj)
		return NULL;
	bsa_heap_iter_entry_prev(itr, hent);
	bheap_percolate_top(itr->heap);
out:
	return bsa_heap_iter_obj(itr, buff);
}

void bsa_heap_iter_entry_reset(bsa_heap_iter_t itr, bsa_heap_iter_entry_t hent)
{
	if (hent->obj && itr->obj_free) {
		itr->obj_free(hent->obj);
	}
	hent->obj = NULL;
}

bsa_heap_iter_pos_t bsa_heap_iter_pos(bsa_heap_iter_t itr)
{
	int i, rc;
	struct bdstr *bdstr;
	struct bsa_heap_iter_pos_s hdr = {0};
	struct bstore_iter_pos_s empty_pos = {0};
	bsa_heap_iter_entry_t hent;
	bsa_heap_iter_pos_t pos;
	bstore_iter_pos_t bs_pos;

	bdstr = bdstr_new(1024);
	if (!bdstr)
		goto err0;
	/* reserve the header */
	rc = bdstr_append_mem(bdstr, &hdr, sizeof(hdr));
	if (rc)
		goto err1;
	TAILQ_FOREACH(hent, &itr->hent_tq, link) {
		if (!hent->obj) {
			rc = bdstr_append_mem(bdstr, &empty_pos,
					      sizeof(empty_pos));
		} else {
			bs_pos = itr->iter_pos(hent->itr);
			if (!bs_pos)
				goto err1;
			rc = bdstr_append_mem(bdstr, bs_pos,
					bs_pos->data_len + sizeof(*bs_pos));
			free(bs_pos);
		}
		if (rc)
			goto err1;
	}
	pos = (void*)bdstr->str;
	BS_POS(pos)->data_len = bdstr->str_len
				- sizeof(struct bstore_iter_pos_s);
	bdstr_detach_buffer(bdstr);
	bdstr_free(bdstr);
	pos->bsa_pos.type = itr->type;
	pos->n = itr->heap->len;
	pos->dir = itr->dir;
	return pos;

err1:
	bdstr_free(bdstr);
err0:
	return NULL;
}

int bsa_heap_iter_pos_set(bsa_heap_iter_t itr, bsa_heap_iter_pos_t pos)
{
	int rc = 0;
	int i;
	void *limit = BS_POS(pos)->data + BS_POS(pos)->data_len;
	bstore_iter_pos_t bs_pos;
	bsa_heap_iter_entry_t hent;

	if (itr->heap->len != pos->n) {
		assert(0 == "iterator-position sub-iterator length mismatch.");
		rc = EINVAL;
		goto out;
	}
	if (itr->type != pos->bsa_pos.type) {
		assert(0 == "iterator-position type mismatch.");
		rc = EINVAL;
		goto out;
	}
	itr->dir = pos->dir;
	bs_pos = pos->bs_pos;
	TAILQ_FOREACH(hent, &itr->hent_tq, link) {
		if ((void*)bs_pos >= limit) {
			assert(0 == "bs_pos length too short");
			rc = EINVAL;
			goto out;
		}
		bsa_heap_iter_entry_reset(itr, hent);
		if (bs_pos->data_len == 0) {
			goto skip;
		}
		rc = itr->iter_pos_set(hent->itr, bs_pos);
		if (rc)
			goto out;
		if (itr->obj_free) {
			/* use non-reentrant */
			hent->obj = itr->iter_obj(hent->itr);
		} else {
			hent->obj = itr->iter_obj_r(hent->itr, hent->data);
		}
		if (hent->obj && itr->hent_xlate) {
			itr->hent_xlate(itr, hent);
		}
	skip:
		bs_pos = ((void*)bs_pos) + sizeof(*bs_pos) + bs_pos->data_len;
	}
	if ((void*)bs_pos != limit) {
		assert(0 == "bs_pos length too long");
		rc = EINVAL;
		goto out;
	}
	bheap_heapify(itr->heap);
out:
	return rc;
}

int bsa_tkn_hist_fwd_key_cmp(const struct btkn_hist_s *a,
			     const struct btkn_hist_s *b)
{
	if (!a) {
		if (!b)
			return 0;
		return 1;
	}
	if (!b) {
		return -1;
	}
	if (a->bin_width < b->bin_width)
		return -1;
	if (a->bin_width > b->bin_width)
		return 1;
	if (a->time < b->time)
		return -1;
	if (a->time > b->time)
		return 1;
	if (a->tkn_id < b->tkn_id)
		return -1;
	if (a->tkn_id > b->tkn_id)
		return 1;
	return 0;
}

int bsa_tkn_hist_bwd_key_cmp(const struct btkn_hist_s *a,
			     const struct btkn_hist_s *b)
{
	if (!a) {
		if (!b)
			return 0;
		return 1;
	}
	if (!b) {
		return -1;
	}
	if (a->bin_width > b->bin_width)
		return -1;
	if (a->bin_width < b->bin_width)
		return 1;
	if (a->time > b->time)
		return -1;
	if (a->time < b->time)
		return 1;
	if (a->tkn_id > b->tkn_id)
		return -1;
	if (a->tkn_id < b->tkn_id)
		return 1;
	return 0;
}

void bsa_tkn_hist_merge(btkn_hist_t a, btkn_hist_t b)
{
	assert(a);
	assert(bsa_tkn_hist_fwd_key_cmp(a, b) == 0);
	a->tkn_count += b->tkn_count;
}

btkn_hist_t bsa_tkn_hist_copy(btkn_hist_t a, btkn_hist_t b)
{
	*b = *a;
	return b;
}

uint32_t bsa_tkn_hist_time(btkn_hist_t a)
{
	return a->time;
}

int bsa_ptn_hist_fwd_key_cmp(const struct bptn_hist_s *a,
			     const struct bptn_hist_s *b)
{
	if (!a) {
		if (!b)
			return 0;
		return 1;
	}
	if (!b) {
		return -1;
	}
	if (a->bin_width < b->bin_width)
		return -1;
	if (a->bin_width > b->bin_width)
		return 1;
	if (a->time < b->time)
		return -1;
	if (a->time > b->time)
		return 1;
	if (a->ptn_id < b->ptn_id)
		return -1;
	if (a->ptn_id > b->ptn_id)
		return 1;
	return 0;
}

int bsa_ptn_hist_bwd_key_cmp(const struct bptn_hist_s *a,
			     const struct bptn_hist_s *b)
{
	if (!a) {
		if (!b)
			return 0;
		return 1;
	}
	if (!b) {
		return -1;
	}
	if (a->bin_width > b->bin_width)
		return -1;
	if (a->bin_width < b->bin_width)
		return 1;
	if (a->time > b->time)
		return -1;
	if (a->time < b->time)
		return 1;
	if (a->ptn_id > b->ptn_id)
		return -1;
	if (a->ptn_id < b->ptn_id)
		return 1;
	return 0;
}

void bsa_ptn_hist_merge(bptn_hist_t a, bptn_hist_t b)
{
	assert(a);
	assert(bsa_ptn_hist_fwd_key_cmp(a, b) == 0);
	a->msg_count += b->msg_count;
}

bptn_hist_t bsa_ptn_hist_copy(bptn_hist_t a, bptn_hist_t b)
{
	*b = *a;
	return b;
}

uint32_t bsa_ptn_hist_time(bptn_hist_t a)
{
	return a->time;
}

void bsa_hist_iter_free(bsa_hist_iter_t itr)
{
	if (itr->hitr_pos)
		free(itr->hitr_pos);
	if (itr->hitr)
		bsa_heap_iter_free(itr->hitr);
	free(itr);
}

bsa_hist_iter_t bsa_hist_iter_new(bsa_t bsa, bsa_iter_type_t type)
{
	bsa_hist_iter_t itr = calloc(1, sizeof(*itr));
	if (!itr)
		goto err0;
	TAILQ_INIT(&itr->head);
	itr->base.bs = &bsa->base;
	itr->hitr = bsa_heap_iter_new(bsa, type);
	if (!itr->hitr)
		goto err1;
	switch (type) {
	case BSA_ITER_TYPE_TKN_HIST:
		itr->hist_key_cmp = (void*)bsa_tkn_hist_fwd_key_cmp;
		itr->hist_merge = (void*)bsa_tkn_hist_merge;
		rbt_init(&itr->rbt, (void*)bsa_tkn_hist_fwd_key_cmp);
		break;
	case BSA_ITER_TYPE_PTN_HIST:
		itr->hist_key_cmp = (void*)bsa_ptn_hist_fwd_key_cmp;
		itr->hist_merge = (void*)bsa_ptn_hist_merge;
		rbt_init(&itr->rbt, (void*)bsa_ptn_hist_fwd_key_cmp);
		break;
	case BSA_ITER_TYPE_COMP_HIST:
		itr->hist_key_cmp = (void*)bsa_comp_hist_fwd_key_cmp;
		itr->hist_merge = (void*)bsa_comp_hist_merge;
		rbt_init(&itr->rbt, (void*)bsa_comp_hist_fwd_key_cmp);
		break;
	default:
		assert(0);
	}
	return itr;

err1:
	free(itr);
err0:
	return NULL;
}

void bsa_hist_iter_buff_reset(bsa_hist_iter_t itr)
{
	/* purge all nodes */
	bsa_hist_t hist;
	itr->curr = NULL;
	itr->rbt.root = NULL;
	while ((hist = TAILQ_FIRST(&itr->head))) {
		TAILQ_REMOVE(&itr->head, hist, link);
		free(hist);
	}
}

bsa_hist_t __hist_dup(bsa_hist_t hist)
{
	bsa_hist_t h = malloc(sizeof(*h));
	if (!h)
		return NULL;
	return memcpy(h, hist, sizeof(*hist));
}

bsa_hist_t bsa_hist_iter_buff_replenish(bsa_hist_iter_t itr, bsa_direction_t dir)
{
	int rc;
	uint32_t t0, t1;
	struct rbn *rbn;
	void *(*step)(bsa_heap_iter_t, void *);
	bsa_hist_t hist;
	step = (dir == BSA_DIRECTION_FWD)?
				(bsa_heap_iter_next):(bsa_heap_iter_prev);

	assert(itr->rbt.root == NULL);

	if (!itr->hobj)
		return NULL;
	/* itr->hobj is the next element for replenishing from previous call */
	/* itr->hobj points to itr->bsa_hist.data or NULL */

	/* save position information before replenish this is needed to recover
	 * the position in set_pos() */
	itr->hitr_hist = *itr->hobj;
	if (itr->hitr_pos)
		free(itr->hitr_pos);
	itr->hitr_pos = bsa_heap_iter_pos(itr->hitr);
	if (!itr->hitr_pos)
		return NULL;

	/* replenishing the buffer */
	t0 = itr->hitr->obj_time(itr->hobj);
	do {
		t1 = itr->hitr->obj_time(itr->hobj);
		if (t0 != t1)
			break;
		rbn = rbt_find(&itr->rbt, itr->hobj);
		if (rbn) {
			/* node existed, just merge the result */
			hist = container_of(rbn, struct bsa_hist_s, rbn);
			itr->hist_merge(&hist->u, itr->hobj);
		} else {
			hist = __hist_dup(&itr->bsa_hist);
			if (!hist)
				return NULL;
			hist->rbn.key = hist->u.data;
			rbt_ins(&itr->rbt, &hist->rbn);
			TAILQ_INSERT_TAIL(&itr->head, hist, link);
		}
		itr->hobj = step(itr->hitr, itr->bsa_hist.u.data);
	} while (itr->hobj);

	rbn = (dir == BSA_DIRECTION_FWD)?rbt_min(&itr->rbt):rbt_max(&itr->rbt);
	assert(rbn);
	return container_of(rbn, struct bsa_hist_s, rbn);
}

/* first() need arg as a search parameter */
void *bsa_hist_iter_first(bsa_hist_iter_t itr, void *arg)
{
	bsa_hist_iter_buff_reset(itr);
	/* copy parameter in */
	itr->hobj = itr->hitr->obj_copy(arg, itr->bsa_hist.u.data);
	itr->hobj = bsa_heap_iter_first(itr->hitr, &itr->bsa_hist.u.data);
	if (!itr->hobj)
		return NULL;
	itr->curr = bsa_hist_iter_buff_replenish(itr, BSA_DIRECTION_FWD);
	if (!itr->curr)
		return NULL;
	/* copy result out */
	return itr->hitr->obj_copy(itr->curr->u.data, arg);
}

/* last() need arg as a search parameter */
void *bsa_hist_iter_last(bsa_hist_iter_t itr, void *arg)
{
	bsa_hist_iter_buff_reset(itr);
	/* copy parameter in */
	itr->hobj = itr->hitr->obj_copy(arg, itr->bsa_hist.u.data);
	itr->hobj = bsa_heap_iter_last(itr->hitr, &itr->bsa_hist.u.data);
	if (!itr->hobj)
		return NULL;
	itr->curr = bsa_hist_iter_buff_replenish(itr, BSA_DIRECTION_BWD);
	if (!itr->curr)
		return NULL;
	/* copy result out */
	return itr->hitr->obj_copy(itr->curr->u.data, arg);
}

void *bsa_hist_iter_next(bsa_hist_iter_t itr, void *buff)
{
	int rc;
	bsa_hist_t hist;
	struct rbn *rbn;
	/* check direction change */

	if (!itr->curr)
		goto no_ent;

	if (itr->hitr->dir != BSA_DIRECTION_FWD) {
		/*
		 * The direction was reverse, hence:
		 *  - hitr current position is at BEFORE buffer--ready to
		 *    replenish the buffer in reverse direction, and
		 *  - hitr_pos is at AFTER buffer (saved position before the
		 *    last replenish).
		 * We need to switch this.
		 */
		bsa_heap_iter_pos_t pos = itr->hitr_pos;
		itr->hitr_pos = bsa_heap_iter_pos(itr->hitr);
		if (!itr->hitr_pos)
			return NULL;
		rc = bsa_heap_iter_pos_set(itr->hitr, pos);
		free(pos);
		if (rc) {
			errno = rc;
			return NULL;
		}
		itr->hobj = bsa_heap_iter_next(itr->hitr, itr->bsa_hist.u.data);
	}

	rbn = rbn_succ(&itr->curr->rbn);
	if (rbn) {
		assert(itr->hist_key_cmp(itr->curr->rbn.key, rbn->key) <= 0);
		itr->curr = container_of(rbn, struct bsa_hist_s, rbn);
		goto out;
	}
	/* need replenish */
	bsa_hist_iter_buff_reset(itr);
	itr->curr = bsa_hist_iter_buff_replenish(itr, BSA_DIRECTION_FWD);
	if (!itr->curr)
		goto no_ent;
out:
	return itr->hitr->obj_copy(itr->curr->u.data, buff);

no_ent:
	return NULL;
}

void *bsa_hist_iter_obj(bsa_hist_iter_t itr, void *buff)
{
	if (itr->curr)
		return itr->hitr->obj_copy(itr->curr->u.data, buff);
	return NULL;
}

bstore_iter_pos_t bsa_hist_iter_pos(bsa_hist_iter_t itr)
{
	bsa_hist_iter_pos_t hist_pos;
	size_t sz = sizeof(*hist_pos) + BS_POS(itr->hitr_pos)->data_len;
	hist_pos = calloc(1, sz);
	if (!hist_pos)
		return NULL;
	BS_POS(hist_pos)->data_len = sz - sizeof(struct bstore_iter_pos_s);
	hist_pos->dir = itr->hitr->dir;
	hist_pos->base.type = itr->hitr->type;
	hist_pos->curr = itr->curr->u;
	hist_pos->hitr_hist = itr->hitr_hist;
	memcpy(&hist_pos->hitr_pos, itr->hitr_pos,
			BS_POS(itr->hitr_pos)->data_len
			+ sizeof(struct bstore_iter_pos_s));
	return BS_POS(hist_pos);
}

int bsa_hist_iter_pos_set(bsa_hist_iter_t itr, bsa_hist_iter_pos_t pos)
{
	int rc = 0;
	union bsa_hist_u key;
	bsa_hist_t hist;
	struct rbn *rbn;

	if (itr->hitr->type != pos->base.type) {
		assert(0 == "Wrong position type");
		rc = EINVAL;
		goto out;
	}

	bsa_hist_iter_buff_reset(itr);
	itr->hitr_hist = pos->hitr_hist;
	itr->hobj = &itr->bsa_hist.u;
	*itr->hobj = pos->hitr_hist;
	rc = bsa_heap_iter_pos_set(itr->hitr, (void*)&pos->hitr_pos);
	if (rc)
		goto out;
	hist = bsa_hist_iter_buff_replenish(itr, pos->dir);
	if (!hist) {
		rc = errno;
		goto out;
	}
	key = pos->curr;
	rbn = rbt_find(&itr->rbt, &key);
	if (!rbn) {
		rc = ENOENT;
		goto out;
	}
	itr->curr = container_of(rbn, struct bsa_hist_s, rbn);
out:
	return rc;
}

static inline int __bsa_tkn_xlate(bsa_t bsa, bstore_t bs, btkn_t tkn)
{
	tkn->tkn_id = 0;
	return __bsa_tkn_add(bsa, tkn);
}

/*
 * __bsa_ptn_xlate() also automatically insert new tokens or pattern into `bsa`.
 */
static int __bsa_ptn_xlate(bsa_t bsa, bstore_t bs, bptn_t ptn)
{
	int rc = 0;
	btkn_t tkn;
	int i;
	for (i = 0; i < ptn->tkn_count; i++) {
		/* u64 = [ id_num(56-bit) | type(8-bit) ] */
		uint64_t tkn_data = ptn->str->u64str[i];
		btkn_id_t tkn_id = tkn_data >> 8;
		btkn_type_t type = tkn_data & 0xFF;
		tkn = bstore_tkn_find_by_id(bs, tkn_id);
		if (!tkn) {
			rc = errno;
			goto out;
		}
		rc = __bsa_tkn_xlate(bsa, bs, tkn);
		if (rc) {
			btkn_free(tkn);
			goto out;
		}
		assert(0 == (tkn->tkn_id >> 56));
		ptn->str->u64str[i] = (tkn->tkn_id<<8) | type;
		btkn_free(tkn);
	}
	ptn->ptn_id = 0;
	rc = __bsa_ptn_find(bsa, ptn, 1);
out:
	return rc;
}

static btkn_id_t __tkn_id_xlate(btkn_id_t id_from,
				bstore_t bs_from, bstore_t bs_to)
{
	btkn_t tkn_from;
	btkn_t tkn_to;
	btkn_id_t id = 0;
	if (!id_from)
		return 0;
	tkn_from = bstore_tkn_find_by_id(bs_from, id_from);
	if (!tkn_from)
		goto out;
	tkn_to = bstore_tkn_find_by_name(bs_to, tkn_from->tkn_str->cstr,
					tkn_from->tkn_str->blen);
	if (!tkn_to)
		goto cleanup0;
	id = tkn_to->tkn_id;

cleanup1:
	btkn_free(tkn_to);
cleanup0:
	btkn_free(tkn_from);
out:
	return id;
}

static inline bcomp_id_t __comp_id_xlate(bcomp_id_t id_from,
				bstore_t bs_from, bstore_t bs_to)
{
	return __tkn_id_xlate(id_from, bs_from, bs_to);
}

static bptn_id_t __ptn_id_xlate(bptn_id_t id_from,
				bstore_t bs_from, bstore_t bs_to)
{
	bptn_id_t id_to = 0;
	bptn_t ptn_from, ptn_to;

	if (!id_from)
		return 0;

	ptn_from = bstore_ptn_find(bs_from, id_from);
	if (!ptn_from)
		goto out;
	ptn_to = __ptn_xlate(ptn_from, bs_from, bs_to);
	if (!ptn_to)
		goto cleanup0;
	id_to = ptn_to->ptn_id;

cleanup1:
	bptn_free(ptn_to);
cleanup0:
	bptn_free(ptn_from);
out:
	return id_to;
}

/*
 * __ptn_xlate() only translate ptn of one bstore into the same ptn of another
 * bstore. There is no store modification.
 */
static bptn_t __ptn_xlate(bptn_t ptn_from, bstore_t bs_from, bstore_t bs_to)
{
	bptn_t ptn_to = bptn_alloc(ptn_from->tkn_count);
	int rc = 0;

	if (!ptn_to)
		goto err0;
	int i;
	ptn_to->tkn_count = ptn_from->tkn_count;
	for (i = 0; i < ptn_from->tkn_count; i++) {
		/* u64 = [ tkn_id(56-bit) | type(8-bit) ] */
		uint64_t tkn_data = ptn_from->str->u64str[i];
		btkn_id_t tkn_id = tkn_data >> 8;
		btkn_type_t type = tkn_data & 0xFF;
		tkn_id = __tkn_id_xlate(tkn_id, bs_from, bs_to);
		if (!tkn_id)
			goto err1;
		ptn_to->str->u64str[i] = (tkn_id<<8) | type;
	}
	ptn_to->str->blen = ptn_from->str->blen;
	/* done translate token IDs ... now, get the pattern info */
	rc = bstore_ptn_find_by_ptnstr(bs_to, ptn_to);
	if (rc) {
		errno = rc;
		goto err1;
	}

	return ptn_to;

err1:
	bptn_free(ptn_to);
err0:
	return NULL;
}

static sos_visit_action_t __bsa_ptn_tkn_add_cb(sos_index_t index,
				     sos_key_t key, sos_idx_data_t *idx_data,
				     int found, void *arg)
{
	struct __visit_ctxt *ctxt = arg;
	if (found)
		return SOS_VISIT_NOP;
	return SOS_VISIT_ADD;
}

static
int __bsa_ptn_tkn_add(bsa_t bsa, bptn_id_t ptn_id, uint64_t tkn_pos,
			btkn_id_t tkn_id)
{
	int rc = 0;
	SOS_KEY(key);
	struct ptn_pos_tkn_s kv;
	struct __visit_ctxt ctxt = {.bsa = bsa, .ptn_pos_tkn = &kv};
	kv.ptn_id = htobe64(ptn_id);
	kv.pos = htobe64(tkn_pos);
	kv.tkn_id = htobe64(tkn_id);
	sos_key_set(key, &kv, sizeof(kv));
	rc = sos_index_visit(sos_attr_index(bsa->ptn_pos_tkn_key_attr),
				key, __bsa_ptn_tkn_add_cb, &ctxt);
	return rc;
}

static int __bsa_sos_open(bsa_t bsa, sos_t *_sos,
			  sos_schema_t *_schema,
			  sos_schema_template_t stmp,
			  struct __attr_entry_s *attr_entries)
{
	int rc, len;
	sos_t sos;
	sos_part_t part;
	sos_schema_t schema;

	len = snprintf(bsa->buff, PATH_MAX, "%s/%s", bsa->store_path, stmp->name);
	if (len >= PATH_MAX) {
		rc = EINVAL;
		goto err0;
	}

	sos = sos_container_open(bsa->buff, SOS_PERM_RW);
	if (!sos) {
		rc = sos_container_new(bsa->buff, bsa->o_mode);
		if (rc)
			goto err0;
		sos = sos_container_open(bsa->buff, SOS_PERM_RW);
		if (!sos) {
			rc = errno;
			goto err0;
		}
	}

	schema = sos_schema_by_name(sos, stmp->name);
	if (!schema) {
		schema = sos_schema_from_template(stmp);
		if (!schema) {
			rc = errno;
			goto err1;
		}
		rc = sos_schema_add(sos, schema);
		if (rc) {
			sos_schema_free(schema);
			/* if schema is added successfully, it will be freed
			 * when sos is closed. */
			goto err1;
		}
	}

	part = sos_part_find(sos, "UNO");
	if (part) {
		/* Main partition exists, do nothing */
		sos_part_put(part);
	} else {
		/* No partition, create it ! */
		rc = sos_part_create(sos, "UNO", NULL);
		if (rc)
			goto err1;
		part = sos_part_find(sos, "UNO");
		assert(part);
		rc = sos_part_state_set(part, SOS_PART_STATE_PRIMARY);
		sos_part_put(part);
		if (rc)
			goto err1;
	}

	*_sos = sos;
	*_schema = schema;

	struct __attr_entry_s *e;
	for (e = &attr_entries[0]; e->_attr_out; e++) {
		sos_attr_t attr = sos_schema_attr_by_name(schema, e->name);
		if (!attr)
			return ENOENT;
		*e->_attr_out = attr;
	}
	return 0;

err1:
	sos_container_close(sos, SOS_COMMIT_ASYNC);
err0:
	return rc;
}

static int __config_handle_store(bsa_t bsa, const char *attr,
				 const char *path)
{
	int rc, len;
	if (bsa->tkn_sos) {
		rc = EEXIST;
		goto err;
	}

	rc = bmkdir_p(path, 0755);
	if (rc == EEXIST)
		rc = 0;
	if (rc)
		goto err;

	len = snprintf(bsa->store_path, PATH_MAX, "%s", path);
	if (len >= PATH_MAX) {
		rc = ENAMETOOLONG;
		goto err;
	}

	rc = __bsa_shmem_open(bsa);
	if (rc)
		goto err;

	/* We are in bsa_open() path. The opened sos will be closed in
	 * bsa_close() on error. Hence, we can simply return rc when an error is
	 * encountered. */

	struct __attr_entry_s tkn_ent[] = {
		{&bsa->tkn_id_attr, "tkn_id"},
		{&bsa->tkn_text_attr, "tkn_text"},
		{&bsa->tkn_type_mask_attr, "tkn_type_mask"},
		{0, 0}
	};

	rc = __bsa_sos_open(bsa, &bsa->tkn_sos, &bsa->token_value_schema,
			    &token_value_schema, tkn_ent);
	if (rc)
		goto err;

	struct __attr_entry_s ptn_ent[] = {
		{&bsa->ptn_id_attr, "ptn_id"},
		{&bsa->ptn_first_seen_attr, "first_seen"},
		{&bsa->ptn_type_ids_attr, "tkn_type_ids"},
		{0, 0}
	};

	rc = __bsa_sos_open(bsa, &bsa->ptn_sos, &bsa->pattern_schema,
			    &pattern_schema, ptn_ent);
	if (rc)
		goto err;

	struct __attr_entry_s ptn_pos_tkn_ent[] = {
		{&bsa->ptn_pos_tkn_key_attr, "ptn_pos_tkn_key"},
		{0, 0}
	};

	rc = __bsa_sos_open(bsa, &bsa->ptn_pos_tkn_sos,
				&bsa->pattern_token_schema,
				&pattern_token_schema, ptn_pos_tkn_ent);
	if (rc)
		goto err;

	binfo("bstore_agg: store path: %s", path);

	return 0;

err:
	return rc;
}

static int __config_handle_bstore(bsa_t bsa, const char *tag,
				  const char *path)
{
	int rc = 0;
	bstore_t bs = bstore_open(tag, path, O_RDWR);
	if (!bs) {
		rc = errno;
		goto err0;
	}
	struct bstore_entry_s *ent = calloc(1, sizeof(*ent));
	if (!ent) {
		rc = ENOMEM;
		goto err1;
	}
	ent->bs = bs;
	TAILQ_INSERT_TAIL(&bsa->bs_tq, ent, link);
	bsa->bs_n++;
	binfo("bstore_agg: Using %s: %s", tag, path);
	return 0;

err1:
	bstore_close(bs);
err0:
	return rc;
}

static int __config_handle_updaters(bsa_t bsa, const char *attr,
				    const char *val)
{
	bsa->n_updaters = atoi(val);
	return 0;
}

static int __config_handle_update_interval(bsa_t bsa, const char *attr,
				    const char *val)
{
	bzero(&bsa->update_interval, sizeof(bsa->update_interval));
	sscanf(val, "%lu.%lu", &bsa->update_interval.tv_sec,
				&bsa->update_interval.tv_usec);
	bsa->update_interval.tv_usec %= 1000000;
	return 0;
}

struct config_table_entry {
	const char *attr;
	int ncmp;
	int (*attr_handler)(bsa_t, const char *attr, const char *val);
};

struct config_table_entry config_table[] = {
	{"store", 0, __config_handle_store},
	{"updaters", 0, __config_handle_updaters},
	{"update_interval", 0, __config_handle_update_interval},
	{"bstore_", 7, __config_handle_bstore},
	{0, 0}
};

static int config_read_cb(char *line, void *ctxt)
{
	bsa_t bsa = ctxt;
	char *val;
	char *attr;
	int rc = 0;
	attr = strtok_r(line, ":", &val);
	if (!attr) {
		berr("Config syntax error: %s", line);
		return EINVAL;
	}

	while (isspace(*val)) {
		val++;
	}

	struct config_table_entry *cte;
	for (cte = config_table; cte->attr; cte++) {
		if (cte->ncmp) {
			if (strncasecmp(cte->attr, attr, cte->ncmp) != 0)
				continue;
		} else {
			if (strcasecmp(cte->attr, attr) != 0)
				continue;
		}
		rc = cte->attr_handler(bsa, attr, val);
		break;
	}
	if (!cte->attr) {
		berr("Config - unknown attr: %s", attr);
		rc = EINVAL;
	}

	return rc;
}

static int __bsa_shmem_open(bsa_t bsa)
{
	int rc = 0;
	int slen;
	if (bsa->shmem_fd > -1 || bsa->shmem != MAP_FAILED) {
		rc = EEXIST;
		goto err0;
	}

	slen = snprintf(bsa->buff, sizeof(bsa->buff), "%s/shmem", bsa->store_path);
	if (slen >= sizeof(bsa->buff)) {
		rc = ENAMETOOLONG;
		goto err0;
	}

	bsa->shmem_fd = open(bsa->buff, O_RDWR | O_CREAT, 0700);
	if (bsa->shmem_fd < 0) {
		rc = errno;
		goto err0;
	}

	rc = ftruncate(bsa->shmem_fd, sizeof(*bsa->shmem));
	if (rc) {
		rc = errno;
		goto err1;
	}

	bsa->shmem = mmap(NULL, sizeof(*bsa->shmem), PROT_READ|PROT_WRITE,
				MAP_SHARED|MAP_LOCKED, bsa->shmem_fd, 0);
	if (bsa->shmem == MAP_FAILED) {
		rc = errno;
		goto err1;
	}

	/* initialize some values */

	if (bsa->shmem->next_ptn_id < 0x0100) {
		bsa->shmem->next_ptn_id = 0x0100;
	}

	if (bsa->shmem->next_tkn_id < 0x0100) {
		bsa->shmem->next_tkn_id = 0x0100;
	}

	return 0;

err1:
	close(bsa->shmem_fd);
	bsa->shmem_fd = -1;
err0:
	return rc;
}

static void __bsa_shmem_close(bsa_t bsa)
{
	if (bsa->shmem != MAP_FAILED) {
		munmap(bsa->shmem, sizeof(*bsa->shmem));
		bsa->shmem = NULL;
	}

	if (bsa->shmem_fd > -1) {
		close(bsa->shmem_fd);
		bsa->shmem_fd = -1;
	}
}

static inline uint64_t __bsa_alloc_tkn_id(bsa_t bsa)
{
	return __sync_fetch_and_add(&bsa->shmem->next_tkn_id, 1);
}

static inline uint64_t __bsa_alloc_ptn_id(bsa_t bsa)
{
	return __sync_fetch_and_add(&bsa->shmem->next_ptn_id, 1);
}

static void __bstore_agg_destroy(bsa_t bsa);

static void __bstore_agg_ref_get(bsa_t bsa)
{
	__sync_add_and_fetch(&bsa->ref_count, 1);
}

static void __bstore_agg_ref_put(bsa_t bsa)
{
	int ref_count = __sync_sub_and_fetch(&bsa->ref_count, 1);
	assert(ref_count >= 0);
	if (ref_count)
		return; /* do nothing */
	__bstore_agg_destroy(bsa);
}

static
int __bstore_agg_updater_init(bsa_updater_t u, bsa_t bsa)
{
	bzero(u, sizeof(*u));
	u->bsa = bsa;
	TAILQ_INIT(&u->bs_tq);
	return 0;
}

void __updater_cleanup(void *arg)
{
	bsa_updater_t u = arg;
	__bstore_agg_ref_put(u->bsa);
}

/*
 * caller should have bsa_lock held
 */
int __bsa_update_bstore_tkn(bsa_t bsa, bstore_t bs)
{
	int rc = 0;
	int itr_count = 0; /* for debugging */
	btkn_t tkn;
	btkn_iter_t itr;
	itr = bstore_tkn_iter_new(bs);
	if (!itr) {
		rc = errno;
		goto out;
	}
	for (tkn = bstore_tkn_iter_first(itr);
			tkn;
			tkn = bstore_tkn_iter_next(itr)) {
		assert(strlen(tkn->tkn_str->cstr) == tkn->tkn_str->blen);
		tkn->tkn_id = 0; /* prep for insertion */
		rc = __bsa_tkn_add(bsa, tkn);
		/* caller owns `tkn` */
		btkn_free(tkn);
		if (rc)
			goto cleanup;
		itr_count++; /* for debugging */
	}

cleanup:
	bstore_tkn_iter_free(itr);
out:
	return rc;
}

int __bsa_update_bstore_ptn(bsa_t bsa, bstore_t bs)
{
	int rc = 0;
	bptn_iter_t itr = NULL;
	bptn_tkn_iter_t bpti = NULL;
	bptn_t ptn;
	btkn_t tkn;
	bptn_id_t bs_ptn_id;
	int tkn_pos;

	itr = bstore_ptn_iter_new(bs);
	if (!itr) {
		rc = errno;
		goto out;
	}
	bpti = bstore_ptn_tkn_iter_new(bs);
	if (!bpti) {
		rc = errno;
		goto cleanup;
	}
	for (ptn = bstore_ptn_iter_first(itr);
			ptn;
			ptn = bstore_ptn_iter_next(itr)) {
		bs_ptn_id = ptn->ptn_id;
		rc = __bsa_ptn_xlate(bsa, bs, ptn);
		/* xlate already add the new ptn */
		/* ptn->ptn_id is bsa ptn ID */
		if (rc) {
			bptn_free(ptn);
			goto cleanup;
		}
		for (tkn_pos = 0; tkn_pos < ptn->tkn_count; tkn_pos++) {
			tkn = bstore_ptn_tkn_iter_find(bpti, bs_ptn_id,
								tkn_pos);
			while (tkn) {
				/* tkn is bs tkn .. need translation */
				rc = __bsa_tkn_xlate(bsa, bs, tkn);
				if (rc) {
					btkn_free(tkn);
					goto cleanup;
				}
				rc = __bsa_ptn_tkn_add(bsa, ptn->ptn_id,
							tkn_pos, tkn->tkn_id);
				if (rc) {
					btkn_free(tkn);
					goto cleanup;
				}
				btkn_free(tkn);
				tkn = bstore_ptn_tkn_iter_next(bpti);
			}

		}
		bptn_free(ptn);
	}

cleanup:
	if (bpti)
		bstore_ptn_tkn_iter_free(bpti);
	if (itr)
		bstore_ptn_iter_free(itr);
out:
	return rc;
}

int __bsa_update_bstore(bsa_t bsa, bstore_t bs)
{
	int rc, _rc;
	/* rc is the first bad _rc */

	_rc = __bsa_update_bstore_tkn(bsa, bs);
	if (_rc) {
		bwarn("__bsa_update_bstore_tkn(%s) error: %d", bs->path, _rc);
	}
	rc = rc?rc:_rc;
	_rc = __bsa_update_bstore_ptn(bsa, bs);
	if (_rc) {
		bwarn("__bsa_update_bstore_ptn(%s) error: %d", bs->path, _rc);
	}
	rc = rc?rc:_rc;
	return rc;
}

/*
 * The core update routine for a bsa updater.
 */
int __updater_update(bsa_updater_t u)
{
	int rc = 0;
	int last_err_rc = 0;
	pthread_mutex_lock(&u->bsa->update_mutex);
	while (!u->bsa->update_need)
		pthread_cond_wait(&u->bsa->update_cond, &u->bsa->update_mutex);
	pthread_mutex_unlock(&u->bsa->update_mutex);

	bstore_entry_t bent;
	TAILQ_FOREACH(bent, &u->bs_tq, updater_link) {
		__bsa_update_bstore(u->bsa, bent->bs);
	}

	pthread_mutex_lock(&u->bsa->update_mutex);
	u->bsa->update_need--;
	pthread_cond_broadcast(&u->bsa->update_cond);
	while (u->bsa->update_need) /* others are still working */
		pthread_cond_wait(&u->bsa->update_cond, &u->bsa->update_mutex);
	pthread_mutex_unlock(&u->bsa->update_mutex);
	return last_err_rc;
}

/*
 * update timer procedure
 */
void *__updater_timer_proc(void *arg)
{
	struct timeval tv, dtv;
	int rc;
	bsa_updater_t u = arg;
	bsa_t bsa = u->bsa;
	pthread_cleanup_push(__updater_cleanup, arg);
	while (1) {
		usleep(bsa->update_interval.tv_sec * 1000000 + bsa->update_interval.tv_usec);
		/*
		 * NOTE: about flock().
		 *
		 * flock() is file-descriptor exclusive. It allows caller to
		 * acquire the exclusive lock of the same file desciptor on a
		 * process multiple times. In such case, the caller needs to
		 * release the lock just once. This is quite dangerous because,
		 * if the caller application is not aware of this, the caller
		 * might have two threads acquiring the exclusive lock at the
		 * same time and both will successfully acquire the lock ...
		 * resulting unprotected critical section.
		 *
		 * The situation above won't happen if the two threads have
		 * different file descriptors that access the same file on the
		 * file system--which happens to be the case for bstore_agg as
		 * a store instance will have only one updater-timer thread
		 * trying to acquire the file lock.
		 *
		 * This flock() is to protect multiple updaters doing
		 * unnecessary updating taks on the same store from multiple
		 * threads/processes.
		 */
		flock(bsa->shmem_fd, LOCK_EX);
		rc = gettimeofday(&tv, NULL);
		assert(rc == 0);
		timersub(&tv, &bsa->shmem->last_update_end, &dtv);
		if (timercmp(&dtv, &bsa->update_interval, <))
			goto skip;

		/* change state && broadcast */
		pthread_mutex_lock(&bsa->update_mutex);
		bsa->update_need = bsa->n_updaters;
		pthread_cond_broadcast(&bsa->update_cond);
		pthread_mutex_unlock(&bsa->update_mutex);

		/* we have to do some update work too */
		rc = __updater_update(u);

		if (rc) {
			bwarn("updater return code: %d\n", rc);
		}

	skip:
		flock(bsa->shmem_fd, LOCK_UN);
	}
	pthread_cleanup_pop(0);
	return NULL;
}

/*
 * updater procedure
 */
void *__updater_proc(void *arg)
{
	int rc;
	bsa_updater_t u = arg;
	while (1) {
		rc = __updater_update(u);

		if (rc) {
			bwarn("updater return code: %d\n", rc);
		}
	}
	return NULL;
}

static int bsa_trylock(bsa_t bsa)
{
	int rc;
	rc = pthread_mutex_trylock(&bsa->update_mutex);
	if (rc)
		return rc;
	rc = flock(bsa->shmem_fd, LOCK_EX|LOCK_NB);
	if (rc) {
		rc = (errno == EWOULDBLOCK)?(EBUSY):(errno);
		pthread_mutex_unlock(&bsa->update_mutex);
		return rc;
	}
	return 0;
}

static void bsa_unlock(bsa_t bsa)
{
	int rc;
	rc = flock(bsa->shmem_fd, LOCK_UN);
	if (rc) {
		bwarn("flock(LOCK_UN) errno: %d", errno);
	}
	pthread_mutex_unlock(&bsa->update_mutex);
}

static void bsa_tryupdate(bsa_t bsa)
{
	bstore_entry_t bent;
	int rc;
	struct timeval tv, dtv;

	if (bsa->n_updaters)
		return; /* updaters will update bsa */

	rc = bsa_trylock(bsa);
	if (rc == EBUSY)
		return;

	gettimeofday(&tv, NULL);
	timersub(&tv, &bsa->shmem->last_update_end, &dtv);
	if (timercmp(&dtv, &bsa->update_interval, <))
		goto out; /* no need to update */

	bsa->shmem->last_update_begin = tv; /* keep for the record */

	assert(rc == 0);
	TAILQ_FOREACH(bent, &bsa->bs_tq, link) {
		__bsa_update_bstore(bsa, bent->bs);
	}

	gettimeofday(&bsa->shmem->last_update_end, NULL);

out:
	bsa_unlock(bsa);
}

static bstore_t bsa_open(struct bstore_plugin_s *plugin, const char *path,
			 int flags, int o_mode)
{
	int rc, fd, i;
	bsa_t bsa;
	fd = open(path, O_RDONLY);
	if (fd == -1)
		goto err0;
	rc = flock(fd, LOCK_EX);
	if (rc)
		goto err1;
	bsa = calloc(1, sizeof(*bsa));
	if (!bsa)
		goto err2;
	bsa->ref_count = 1;
	TAILQ_INIT(&bsa->bs_tq);
	bsa->base.plugin = plugin;
	if (!o_mode)
		o_mode = 0755;
	/* default update interval is 60 sec */
	bsa->update_interval.tv_sec = 60;
	bsa->update_interval.tv_usec = 0;
	bsa->o_mode = o_mode;
	bsa->shmem = MAP_FAILED;
	bsa->shmem_fd = -1;
	bsa->base.path = strdup(path);
	if (!bsa->base.path)
		goto err3;

	rc = bprocess_file_by_line_w_comment(path, config_read_cb, bsa);
	if (rc) {
		errno = rc;
		goto err3;
	}

	/* update_mutex is used in updaters and tryupdate */
	pthread_mutex_init(&bsa->update_mutex, NULL);

	/* updaters initialization */
	if (bsa->n_updaters > 0) {
		bsa->update_need = 0;
		pthread_cond_init(&bsa->update_cond, NULL);

		for (i = 0; i < bsa->n_updaters; i++) {
			__bstore_agg_updater_init(&bsa->updater[i], bsa);
		}
		i = 0;
		/* evenly spread bstore among bsa updaters */
		bstore_entry_t ent;
		bsa_updater_t u;
		TAILQ_FOREACH(ent, &bsa->bs_tq, link) {
			u = &bsa->updater[i];
			TAILQ_INSERT_TAIL(&u->bs_tq, ent, updater_link);
			i++;
		}
		for (i = 0; i < bsa->n_updaters; i++) {
			void *(*fn)(void*);
			if (i == 0) {
				fn = __updater_timer_proc;
			} else {
				fn = __updater_proc;
			}
			u = &bsa->updater[i];
			__bstore_agg_ref_get(bsa); /* will be put in thread cleanup */
			rc = pthread_create(&u->thread, NULL, fn, u);
			if (rc == 0) {
				u->init_state = 1;
			} else {
				__bstore_agg_ref_put(bsa);
				goto err3;
			}
		}
	} else {
		bsa_tryupdate(bsa);
	}

	flock(fd, LOCK_UN);
	close(fd);
	return &bsa->base;

err3:
	bsa_close(&bsa->base);
err2:
	flock(fd, LOCK_UN);
err1:
	close(fd);
err0:
	return NULL;
}

static void __bstore_agg_destroy(bsa_t bsa)
{
	bstore_entry_t ent;
	int i;
	bsa_updater_t u;

	while ((ent = TAILQ_FIRST(&bsa->bs_tq))) {
		TAILQ_REMOVE(&bsa->bs_tq, ent, link);
		bstore_close(ent->bs);
		free(ent);
	}
	if (bsa->tkn_sos)
		sos_container_close(bsa->tkn_sos, SOS_COMMIT_ASYNC);
	if (bsa->ptn_sos)
		sos_container_close(bsa->ptn_sos, SOS_COMMIT_ASYNC);
	if (bsa->ptn_pos_tkn_sos)
		sos_container_close(bsa->ptn_pos_tkn_sos, SOS_COMMIT_ASYNC);
	if (bsa->base.path)
		free(bsa->base.path);
	__bsa_shmem_close(bsa);
	free(bsa);
}

static
void bsa_close(bstore_t bs)
{
	/* stop all updater threads */
	int i;
	bsa_t bsa = (void*)bs;
	bsa_updater_t u;
	for (i = 0; i < bsa->n_updaters; i++) {
		u = &bsa->updater[i];
		if (u->init_state > 0) {
			pthread_cancel(u->thread);
		}
	}

	__bstore_agg_ref_put((void*)bs);
}

static void btkn_bsakey(btkn_t tkn, sos_key_t key)
{
	assert(tkn->tkn_str->blen == strlen(tkn->tkn_str->cstr));
	ods_key_value_t kv = key->as.ptr;
	memcpy(kv->value, tkn->tkn_str->cstr, tkn->tkn_str->blen);
	kv->value[tkn->tkn_str->blen] = '\0';
	kv->len = tkn->tkn_str->blen + 1;
}

static sos_visit_action_t __bsa_tkn_add_cb(sos_index_t index,
				     sos_key_t key, sos_idx_data_t *idx_data,
				     int found, void *arg)
{
	struct __visit_ctxt *ctxt = arg;

	int rc;
	tkn_value_t tkn_value;
	struct sos_value_s v_, *v;
	size_t sz;
	sos_obj_t tkn_obj;
	sos_obj_ref_t *ref = (sos_obj_ref_t *)idx_data;
	btkn_id_t tkn_id;
	SOS_KEY(id_key);

	if (!found)
		goto new_token;

update_token:
	/* in-store token info contains nothing other than ID as the information
	 * will be aggregated from sub-stores when query. */
	tkn_obj = sos_ref_as_obj(ctxt->bsa->tkn_sos, *ref);
	tkn_value = sos_obj_ptr(tkn_obj);

	/* Update only the id for the memory tkn */
	ctxt->tkn->tkn_id = tkn_value->tkn_id;
	sos_obj_put(tkn_obj);
	return SOS_VISIT_NOP;

new_token:
	/* new token */

	tkn_obj = sos_obj_new(ctxt->bsa->token_value_schema);
	if (!tkn_obj)
		goto err_0;

	tkn_value = sos_obj_ptr(tkn_obj);
	tkn_value->tkn_count = ctxt->tkn->tkn_count;

	sz = ctxt->tkn->tkn_str->blen+1;
	v = sos_array_new(&v_, ctxt->bsa->tkn_text_attr, tkn_obj, sz);
	if (!v) {
		berr("Failed to allocate array.");
		assert(0);
		goto err_1;
	}

	memcpy(v->data->array.data.byte_, ctxt->tkn->tkn_str->cstr, sz-1);
	v->data->array.data.byte_[ctxt->tkn->tkn_str->blen] = '\0';
	sos_value_put(v);

	/* Squash BTKN_TYPE_TEXT (i.e. unrecognized) if WORD or
	 * HOSTNAME is present */
	if (btkn_has_type(ctxt->tkn, BTKN_TYPE_WORD)
	    | btkn_has_type(ctxt->tkn, BTKN_TYPE_HOSTNAME))
		ctxt->tkn->tkn_type_mask &= ~BTKN_TYPE_MASK(BTKN_TYPE_TEXT);
	tkn_value->tkn_type_mask = ctxt->tkn->tkn_type_mask;
	tkn_id = __bsa_alloc_tkn_id(ctxt->bsa);
	ctxt->tkn->tkn_id = tkn_value->tkn_id = tkn_id;

	/* insert ID index */
	sos_key_set(id_key, &tkn_id, sizeof(tkn_id));
	rc = sos_index_insert(sos_attr_index(ctxt->bsa->tkn_id_attr), id_key, tkn_obj);
	if (rc) {
		berr("Cannot insert tkn_id index");
		goto err_2;
	}
	/* the text index will be handled by the `visit` mechanism */
out:
	*ref = sos_obj_ref(tkn_obj);
	sos_obj_put(tkn_obj);
	return SOS_VISIT_ADD;

err_2:
err_1:
	sos_obj_delete(tkn_obj);
	sos_obj_put(tkn_obj);
err_0:
	return SOS_VISIT_NOP;
}

/*
 * This `tkn_add` functionality is for internal use.
 */
static
int __bsa_tkn_add(bsa_t bsa, btkn_t tkn)
{
	struct __visit_ctxt _ctxt;
	int rc;
	SOS_KEY(text_key);
	btkn_bsakey(tkn, text_key);
	_ctxt.bsa = bsa;
	_ctxt.tkn = tkn;
	rc = sos_index_visit(sos_attr_index(bsa->tkn_text_attr), text_key,
							__bsa_tkn_add_cb, &_ctxt);
	return rc;
}

static
btkn_id_t bsa_tkn_add(bstore_t bs, btkn_t tkn)
{
	bwarn("bstore_agg does not support tkn_add()");
	return ENOSYS;
}

static
int bsa_tkn_add_with_id(bstore_t bs, btkn_t tkn)
{
	bwarn("bstore_agg does not support tkn_add_with_id()");
	return ENOSYS;
}

static
btkn_t __bsa_make_tkn(bsa_t bsa, sos_obj_t tkn_obj)
{
	btkn_t tkn = NULL;
	btkn_t _tkn;
	tkn_value_t sos_tkn;
	sos_value_t sos_str;
	bstore_entry_t ent;

	sos_tkn = sos_obj_ptr(tkn_obj);
	sos_str = sos_value(tkn_obj, bsa->tkn_text_attr);
	tkn = btkn_alloc(sos_tkn->tkn_id, sos_tkn->tkn_type_mask,
			 sos_str->data->array.data.char_,
			 sos_str->data->array.count - 1);
	sos_value_put(sos_str);

	if (!tkn) {
		errno = ENOMEM;
		goto out;
	}
	tkn->tkn_count = 0;
	tkn->tkn_type_mask = 0;

	/* collect statistics from bstores */
	TAILQ_FOREACH(ent, &bsa->bs_tq, link) {
		_tkn = bstore_tkn_find_by_name(ent->bs,
						tkn->tkn_str->cstr,
						tkn->tkn_str->blen);
		if (!_tkn)
			continue; /* some store might not have it */
		tkn->tkn_count += _tkn->tkn_count;
		tkn->tkn_type_mask |= _tkn->tkn_type_mask;
		btkn_free(_tkn);
	}

out:
	return tkn;
}

static
btkn_t bsa_tkn_find_by_id(bstore_t bs, btkn_id_t tkn_id)
{
	btkn_t tkn = NULL;
	bsa_t bsa = (bsa_t)bs;
	sos_obj_t tkn_obj;
	SOS_KEY(id_key);

	sos_key_set(id_key, &tkn_id, sizeof(tkn_id));
	tkn_obj = sos_obj_find(bsa->tkn_id_attr, id_key);
	if (!tkn_obj)
		goto out_0;
	tkn = __bsa_make_tkn(bsa, tkn_obj);
	sos_obj_put(tkn_obj);
out_0:
	return tkn;
}

static
btkn_t bsa_tkn_find_by_name(bstore_t bs, const char *text, size_t text_len)
{
	bsa_t bsa = (bsa_t)bs;
	btkn_t bsa_token;
	btkn_t token;
	struct bstore_entry_s *ent;
	int rc;
	int found = 0;

	bsa_token = btkn_alloc(0, 0, text, text_len);
	if (!bsa_token)
		goto err0;

	TAILQ_FOREACH(ent, &bsa->bs_tq, link) {
		token = bstore_tkn_find_by_name(ent->bs, text, text_len);
		if (token) {
			/* merge token info into bsa_token */
			found = 1;
			bsa_token->tkn_count += token->tkn_count;
			bsa_token->tkn_type_mask |= token->tkn_type_mask;
			btkn_free(token);
		}
		/* else, just do nothing */
	}

	if (found) {
		/* valid token .. insert it */
		rc = __bsa_tkn_add(bsa, bsa_token);
		if (rc)
			goto err1;
	} else {
		errno = ENOENT;
		goto err1;
	}

	return bsa_token;

err1:
	btkn_free(bsa_token);
err0:
	return NULL;
}

static
bstore_iter_pos_t bsa_tkn_iter_pos(btkn_iter_t itr)
{
	int rc;
	sos_pos_t sos_pos;
	bsa_tkn_iter_pos_t pos;
	size_t sz;

	sos_pos = sos_iter_pos(BSA_TKN_ITER(itr)->sitr);
	if (!sos_pos) {
		return NULL;
	}
	sz = sizeof(*pos) + sos_pos->data_len;
	pos = calloc(1, sz);
	if (!pos) {
		free(sos_pos);
		return NULL;
	}
	BS_POS(pos)->data_len = sz - sizeof(struct bstore_iter_pos_s);
	BSA_POS(pos)->type = BSA_ITER_TYPE_TKN;
	memcpy(&pos->sos_pos, sos_pos, sos_pos_sz(sos_pos));
	free(sos_pos);
	return &pos->bsa_pos.bs_pos;
}

static
int bsa_tkn_iter_pos_set(btkn_iter_t itr, bstore_iter_pos_t _pos)
{
	bsa_tkn_iter_pos_t pos = (void*)_pos;
	return sos_iter_set(BSA_TKN_ITER(itr)->sitr, &pos->sos_pos);
}

static
btkn_iter_t bsa_tkn_iter_new(bstore_t bs)
{
	bsa_t bsa = (void*)bs;
	bsa_tkn_iter_t itr = calloc(1, sizeof(*itr));
	if (!itr)
		return NULL;
	itr->base.bs = bs;
	itr->sitr = sos_attr_iter_new(bsa->tkn_id_attr);
	if (!itr->sitr) {
		free(itr);
		return NULL;
	}
	return &itr->base;
}

static
void bsa_tkn_iter_free(btkn_iter_t i)
{
	bsa_tkn_iter_t itr = (void*)i;
	if (itr->sitr) {
		sos_iter_free(itr->sitr);
		itr->sitr = NULL;
	}
	free(itr);
}

static
uint64_t bsa_tkn_iter_card(btkn_iter_t i)
{
	return sos_iter_card(((bsa_tkn_iter_t)i)->sitr);
}

static
btkn_t bsa_tkn_iter_obj(btkn_iter_t _itr);

static
btkn_t bsa_tkn_iter_first(btkn_iter_t _itr)
{
	int rc;
	bsa_tkn_iter_t itr = (void*)_itr;

	rc = sos_iter_begin(itr->sitr);
	if (rc) {
		errno = rc;
		return NULL;
	}

	return bsa_tkn_iter_obj(_itr);
}

static
btkn_t bsa_tkn_iter_obj(btkn_iter_t _itr)
{
	bsa_tkn_iter_t itr = (void*)_itr;
	bsa_t bsa = (bsa_t)_itr->bs;
	sos_obj_t obj = sos_iter_obj(itr->sitr);
	btkn_t tkn;
	if (!obj)
		return NULL;
	tkn = __bsa_make_tkn(bsa, obj);
	sos_obj_put(obj);
	return tkn;
}

static
btkn_t bsa_tkn_iter_next(btkn_iter_t _itr)
{
	int rc;
	bsa_tkn_iter_t itr = (void*)_itr;

	rc = sos_iter_next(itr->sitr);
	if (rc) {
		errno = rc;
		return NULL;
	}

	return bsa_tkn_iter_obj(_itr);
}

static
btkn_t bsa_tkn_iter_prev(btkn_iter_t _itr)
{
	int rc;
	bsa_tkn_iter_t itr = (void*)_itr;

	rc = sos_iter_prev(itr->sitr);
	if (rc) {
		errno = rc;
		return NULL;
	}

	return bsa_tkn_iter_obj(_itr);
}

static
btkn_t bsa_tkn_iter_last(btkn_iter_t _itr)
{
	int rc;
	bsa_tkn_iter_t itr = (void*)_itr;

	rc = sos_iter_end(itr->sitr);
	if (rc) {
		errno = rc;
		return NULL;
	}

	return bsa_tkn_iter_obj(_itr);
}

static
int bsa_msg_add(bstore_t bs, struct timeval *tv, bmsg_t msg)
{
	berr("bstore_agg is a read-only bstore");
	return ENOSYS;
}

static
bstore_iter_pos_t bsa_msg_iter_pos(bmsg_iter_t _itr)
{
	return (bstore_iter_pos_t)bsa_heap_iter_pos((void*)_itr);
}

static
int bsa_msg_iter_pos_set(bmsg_iter_t itr, bstore_iter_pos_t pos)
{
	return bsa_heap_iter_pos_set((void*)itr, (bsa_heap_iter_pos_t)pos);
}

static
int bsa_heap_iter_entry_msg_fwd_cmp(bsa_heap_iter_entry_t a,
				    bsa_heap_iter_entry_t b)
{
	bmsg_t ma = a->obj;
	bmsg_t mb = b->obj;
	/* NULL == inf so that NULL sink to the bottom of the heap */
	if (!ma) {
		if (mb)
			return 1;
		return 0;
	}
	if (!mb)
		return -1;
	if (timercmp(&ma->timestamp, &mb->timestamp, <))
		return -1;
	if (timercmp(&ma->timestamp, &mb->timestamp, >))
		return 1;
	if (ma->comp_id < mb->comp_id)
		return -1;
	if (ma->comp_id > mb->comp_id)
		return 1;
	return 0;
}

static
int bsa_heap_iter_entry_msg_bwd_cmp(bsa_heap_iter_entry_t a,
				    bsa_heap_iter_entry_t b)
{
	bmsg_t ma = a->obj;
	bmsg_t mb = b->obj;
	/* NULL == inf so that NULL sink to the bottom of the heap */
	if (!ma) {
		if (mb)
			return 1;
		return 0;
	}
	if (!mb)
		return -1;
	if (timercmp(&ma->timestamp, &mb->timestamp, >))
		return -1;
	if (timercmp(&ma->timestamp, &mb->timestamp, <))
		return 1;
	if (ma->comp_id > mb->comp_id)
		return -1;
	if (ma->comp_id < mb->comp_id)
		return 1;
	return 0;
}

static
int bsa_heap_iter_entry_tkn_hist_fwd_cmp(bsa_heap_iter_entry_t a,
					 bsa_heap_iter_entry_t b)
{
	return bsa_tkn_hist_fwd_key_cmp(a->obj, b->obj);
}

static
int bsa_heap_iter_entry_tkn_hist_bwd_cmp(bsa_heap_iter_entry_t a,
					 bsa_heap_iter_entry_t b)
{
	return bsa_tkn_hist_bwd_key_cmp(a->obj, b->obj);
}

static
int bsa_heap_iter_entry_ptn_hist_fwd_cmp(bsa_heap_iter_entry_t a,
					 bsa_heap_iter_entry_t b)
{
	return bsa_ptn_hist_fwd_key_cmp(a->obj, b->obj);
}

static
int bsa_heap_iter_entry_ptn_hist_bwd_cmp(bsa_heap_iter_entry_t a,
					 bsa_heap_iter_entry_t b)
{
	return bsa_ptn_hist_bwd_key_cmp(a->obj, b->obj);
}

static int bsa_heap_iter_entry_comp_hist_fwd_cmp(bsa_heap_iter_entry_t a,
						bsa_heap_iter_entry_t b)
{
	return bsa_comp_hist_fwd_key_cmp(a->obj, b->obj);
}

static int bsa_heap_iter_entry_comp_hist_bwd_cmp(bsa_heap_iter_entry_t a,
						bsa_heap_iter_entry_t b)
{
	return bsa_comp_hist_bwd_key_cmp(a->obj, b->obj);
}

static
void bsa_msg_iter_free(bmsg_iter_t i);

static
bmsg_iter_t bsa_msg_iter_new(bstore_t bs)
{
	bsa_heap_iter_t itr = bsa_heap_iter_new(BSA(bs), BSA_ITER_TYPE_MSG);
	if (!itr)
		return NULL;
	return &itr->base;
}

static
void bsa_msg_iter_free(bmsg_iter_t _itr)
{
	bsa_heap_iter_free((void*)_itr);
}

static
uint64_t bsa_msg_iter_card(bmsg_iter_t _itr)
{
	return bsa_heap_iter_card((void*)_itr);
}

static
bmsg_t bsa_msg_iter_find(bmsg_iter_t _itr,
			time_t start, bptn_id_t ptn_id, bcomp_id_t comp_id,
			bmsg_cmp_fn_t cmp_fn, void *ctxt)
{
	int rc;
	bsa_heap_iter_t itr = (void*)_itr;
	bsa_heap_iter_entry_t hent;
	bptn_t ptn = NULL;
	bptn_t bs_ptn = NULL;
	bcomp_id_t bs_comp_id = 0;
	bptn_id_t bs_ptn_id = 0;

	if (ptn_id) {
		ptn = bsa_ptn_find(itr->base.bs, ptn_id);
		if (!ptn)
			goto err0;
	}

	BHEAP_FOREACH(hent, itr->heap) {
		bsa_heap_iter_entry_reset(itr, hent);

		/* comp_id and ptn_id need translation */
		if (comp_id) {
			bs_comp_id = __comp_id_xlate(comp_id, itr->base.bs,
								hent->itr->bs);
			if (!bs_comp_id) {
				/* bs might not have this comp_id */
				continue;
			}
		}

		if (ptn_id) {
			bs_ptn = __ptn_xlate(ptn, itr->base.bs, hent->itr->bs);
			if (!bs_ptn) {
				/* bs might not have this ptn */
				continue;
			}
			bs_ptn_id = bs_ptn->ptn_id;
		}

		hent->obj = bstore_msg_iter_find(hent->itr, start,
				bs_ptn_id, bs_comp_id, cmp_fn, ctxt);
		if (hent->obj) {
			itr->hent_xlate(itr, hent);
		}
		if (bs_ptn)
			bptn_free(bs_ptn);
	}
	bheap_heapify(itr->heap);

	if (ptn)
		bptn_free(ptn);

	hent = bheap_get_top(itr->heap);
	return hent->obj; /* hent->obj can be NULL */

err0:
	return NULL;
}

static
bmsg_t bsa_msg_iter_obj(bmsg_iter_t _itr)
{
	return bsa_heap_iter_obj((void*)_itr, NULL);
}

static
bmsg_t bsa_msg_iter_next(bmsg_iter_t _itr)
{
	return bsa_heap_iter_next((void*)_itr, NULL);
}

static
bmsg_t bsa_msg_iter_prev(bmsg_iter_t _itr)
{
	return bsa_heap_iter_prev((void*)_itr, NULL);
}

static
bmsg_t bsa_msg_iter_first(bmsg_iter_t _itr)
{
	return bsa_heap_iter_first((void*)_itr, NULL);
}

static
bmsg_t bsa_msg_iter_last(bmsg_iter_t _itr)
{
	return bsa_heap_iter_last((void*)_itr, NULL);
}

static sos_visit_action_t __bsa_ptn_add_cb(sos_index_t index,
				     sos_key_t key, sos_idx_data_t *idx_data,
				     int found, void *arg)
{
	struct __visit_ctxt *ctxt = arg;
	bptn_t ptn = ctxt->ptn;
	bsa_t bsa = ctxt->bsa;
	sos_obj_ref_t *ref = (sos_obj_ref_t *)idx_data;
	sos_obj_t ptn_obj;
	sptn_value_t ptn_val;
	bptn_id_t ptn_id;
	SOS_KEY(id_key);
	SOS_KEY(ts_key);
	int rc;

	if (!found) {
		if (ctxt->add)
			goto new_ptn;
		ptn->ptn_id = 0;
		return SOS_VISIT_NOP;
	}

ptn_exist:
	/* just update in-memory pattern id ... */
	ptn_obj = sos_ref_as_obj(ctxt->bsa->ptn_sos, *ref);
	ptn_val = sos_obj_ptr(ptn_obj);
	ptn->ptn_id = ptn_val->ptn_id;
	if (!ctxt->add) /* this is a find operation */
		goto no_first_seen_update;

	/* check if the new `first_seen` is earlier than the previous one ...
	 * if so we need an index update */
	if (ptn->first_seen.tv_sec > ptn_val->first_seen.secs)
		goto no_first_seen_update;
	if (ptn->first_seen.tv_sec == ptn_val->first_seen.secs &&
			ptn->first_seen.tv_usec >= ptn_val->first_seen.usecs)
		goto no_first_seen_update;
	/* remove old index */
	sos_key_set(ts_key, &ptn_val->first_seen, sizeof(ptn_val->first_seen));
	rc = sos_index_remove(sos_attr_index(ctxt->bsa->ptn_first_seen_attr),
				ts_key, ptn_obj);
	assert(rc == 0);
	/* add new index */
	ptn_val->first_seen.secs = ptn->first_seen.tv_sec;
	ptn_val->first_seen.usecs = ptn->first_seen.tv_usec;
	sos_key_set(ts_key, &ptn_val->first_seen, sizeof(ptn_val->first_seen));
	rc = sos_index_insert(sos_attr_index(ctxt->bsa->ptn_first_seen_attr),
				ts_key, ptn_obj);
	assert(rc == 0);
no_first_seen_update:
	/* copy-out all stats */
	ptn->first_seen.tv_sec = ptn_val->first_seen.secs;
	ptn->first_seen.tv_usec = ptn_val->first_seen.usecs;
	ptn->last_seen.tv_sec = ptn_val->last_seen.secs;
	ptn->last_seen.tv_usec = ptn_val->last_seen.usecs;
	ptn->count = ptn_val->count;
	ptn->tkn_count = ptn_val->tkn_count;
	sos_obj_put(ptn_obj);
	return SOS_VISIT_NOP;

new_ptn:
	/* new pattern */
	ptn_obj = sos_obj_new(ctxt->bsa->pattern_schema);
	if (!ptn_obj)
		goto err0;
	ptn_val = sos_obj_ptr(ptn_obj);
	struct sos_value_s _v;
	sos_value_t v;
	size_t sz = ptn->tkn_count * sizeof(bptn_id_t);
	v = sos_array_new(&_v, bsa->ptn_type_ids_attr, ptn_obj, sz);
	if (!v)
		goto err1;
	sos_value_memcpy(v, ptn->str->cstr, sz);
	sos_value_put(v);

	ptn->ptn_id = ptn_val->ptn_id = ptn_id = __bsa_alloc_ptn_id(bsa);
	ptn_val->tkn_count = ptn->tkn_count;
	ptn_val->first_seen.secs = ptn->first_seen.tv_sec;
	ptn_val->first_seen.usecs = ptn->first_seen.tv_usec;

	sos_key_set(id_key, &ptn_id, sizeof(ptn_id));
	rc = sos_index_insert(sos_attr_index(ctxt->bsa->ptn_id_attr), id_key, ptn_obj);
	if (rc)
		goto err2;

	sos_key_set(ts_key, &ptn_val->first_seen, sizeof(ptn_val->first_seen));
	rc = sos_index_insert(sos_attr_index(ctxt->bsa->ptn_first_seen_attr), ts_key, ptn_obj);
	if (rc)
		goto err2;

	*ref = sos_obj_ref(ptn_obj);
	sos_obj_put(ptn_obj);
	return SOS_VISIT_ADD;

err2:
err1:
	sos_obj_delete(ptn_obj);
	sos_obj_put(ptn_obj);
err0:
	return SOS_VISIT_NOP;
}

static int __bsa_ptn_find(bsa_t bsa, bptn_t ptn, int add)
{
	int rc = 0;
	bptn_id_t ptn_id;
	sptn_value_t ptn_value;
	sos_obj_t ptn_obj;
	SOS_KEY_SZ(stack_key, 2048);
	sos_key_t ptn_key;
	struct __visit_ctxt _ctxt;

	if (ptn->str->blen <= 2048)
		ptn_key = stack_key;
	else
		ptn_key = sos_key_new(ptn->str->blen);

	/* If the pattern is already present, return it's ptn_id */
	size_t tkn_count = ptn->str->blen / sizeof(ptn->str->u64str[0]);
	sos_key_set(ptn_key, ptn->str->cstr, ptn->str->blen);

	_ctxt.bsa = bsa;
	_ctxt.ptn = ptn;
	_ctxt.add = add;

	rc = sos_index_visit(sos_attr_index(bsa->tkn_text_attr), ptn_key,
						__bsa_ptn_add_cb, &_ctxt);
	if (ptn_key != stack_key)
		sos_key_put(ptn_key);
	if (!rc && ptn->ptn_id == 0)
		rc = ENOENT;
	return rc;
}

static
bptn_id_t bsa_ptn_add(bstore_t bs, struct timeval *tv, bstr_t ptn)
{
	bwarn("bstore_agg is a read-only bstore.");
	errno = ENOSYS;
	return 0;
}

static
bptn_t __bsa_make_ptn(bsa_t bsa, sos_obj_t obj)
{
	bstore_entry_t bse;
	struct sos_value_s _v, *v;
	bptn_t bptn;
	sptn_value_t sptn;

	if (!obj)
		goto err0;

	sptn = sos_obj_ptr(obj); /* this doesn't take reference
				  * ==> no need to sos_obj_put() */
	assert(sptn);
	bptn = bptn_alloc(sptn->tkn_count);
	if (!bptn)
		goto err0;

	bptn->ptn_id = sptn->ptn_id;

	/* copy-out pattern args ([<type,token>]) */
	bptn->tkn_count = sptn->tkn_count;
	bptn->str->blen = bptn->tkn_count * sizeof(uint64_t);
	v = sos_value_init(&_v, obj, bsa->ptn_type_ids_attr);
	if (!v)
		goto err1;
	memcpy(bptn->str->u64str, v->data->array.data.uint64_, bptn->str->blen);
	sos_value_put(v);

	/* statistics need to re-collect from bstores */
	if (sizeof(bptn->first_seen.tv_sec) == 8) {
		bptn->first_seen.tv_sec = (((uint64_t)-1)<<1)>>1;
	} else {
		bptn->first_seen.tv_sec = (((uint32_t)-1)<<1)>>1;
	}
	bptn->first_seen.tv_usec = 0;
	bptn->last_seen.tv_sec = 0;
	bptn->last_seen.tv_usec = 0;
	bptn->count = 0;

	TAILQ_FOREACH(bse, &bsa->bs_tq, link) {
		bptn_t _ptn = __ptn_xlate(bptn, &bsa->base, bse->bs);
		if (!_ptn)
			continue; /* bptn may not exist in all bstores */
		/* merge attributes */
		if (timercmp(&bptn->first_seen, &_ptn->first_seen, >)) {
			bptn->first_seen = _ptn->first_seen;
		}
		if (timercmp(&bptn->last_seen, &_ptn->last_seen, <)) {
			bptn->last_seen = _ptn->last_seen;
		}
		bptn->count += _ptn->count;

		bptn_free(_ptn);
	}

	return bptn;

err1:
	bptn_free(bptn);
err0:
	return NULL;
}

static
bptn_t bsa_ptn_find(bstore_t bs, bptn_id_t ptn_id)
{
	bsa_t bsa = (void*)bs;
	bptn_t ptn;
	sos_obj_t obj;
	SOS_KEY(id_key);

	sos_key_set(id_key, &ptn_id, sizeof(ptn_id));
	obj = sos_obj_find(bsa->ptn_id_attr, id_key);
	if (!obj)
		goto err0;

	ptn = __bsa_make_ptn(bsa, obj);
	sos_obj_put(obj); /* put obj regardless of make ptn error */
	if (!ptn)
		goto err0;

	return ptn;

err0:
	return NULL;
}

static int bsa_ptn_find_by_ptnstr(bstore_t bs, bptn_t ptn)
{
	return __bsa_ptn_find((void*)bs, ptn, 0);
}

static
int bsa_ptn_iter_reinit(bsa_ptn_iter_t itr, bsa_iter_type_t type)
{
	int rc = 0;
	bsa_t bsa = (void*)itr->base.bs;
	if (itr->sitr)
		sos_iter_free(itr->sitr);
	itr->type = type;
	switch (type) {
	case BSA_ITER_TYPE_PTN_ID:
		itr->sitr = NULL;
		break;
	case BSA_ITER_TYPE_PTN_FIRST_SEEN:
		itr->sitr = sos_attr_iter_new(bsa->ptn_first_seen_attr);
		if (!itr->sitr)
			rc = errno;
		break;
	default:
		assert(0 == "Invalid bsa_iter_type");
		rc = errno = EINVAL;
	}
	return rc;
}

static
bstore_iter_pos_t bsa_ptn_iter_pos(bptn_iter_t _itr)
{
	bsa_ptn_iter_t itr = (void*)_itr;
	sos_pos_t sos_pos = NULL;
	bsa_ptn_iter_pos_t pos = NULL;
	int rc;
	size_t sz;

	/* size calculation */
	switch (itr->type) {
	case BSA_ITER_TYPE_PTN_ID:
		sz = sizeof(*pos);
		break;
	case BSA_ITER_TYPE_PTN_FIRST_SEEN:
		sos_pos = sos_iter_pos(itr->sitr);
		if (!sos_pos)
			goto err;
		sz = sizeof(*pos) + sos_pos->data_len;
		break;
	default:
		assert(0 == "Invalid bsa_iter_type");
		errno = EINVAL;
		goto err;
	}

	/* init */
	pos = calloc(1, sz);
	if (!pos)
		goto err;
	BSA_POS(pos)->type = itr->type;
	BS_POS(pos)->data_len = sz - sizeof(struct bstore_iter_pos_s);
	/* position setting */
	if (sos_pos) {
		memcpy(&pos->sos_pos, sos_pos, sos_pos_sz(sos_pos));
		free(sos_pos);
	} else {
		pos->ptn_id = itr->ptn_id;
	}
	return BS_POS(pos);

err:
	if (pos)
		free(pos);
	if (sos_pos)
		free(sos_pos);
	return NULL;
}

static
int bsa_ptn_iter_pos_set(bptn_iter_t _itr, bstore_iter_pos_t _pos)
{
	int rc;
	bsa_ptn_iter_pos_t pos = (void*)_pos;
	SOS_KEY(id_key);
	bsa_ptn_iter_t itr = (void*)_itr;
	bsa_t bsa = (void*)itr->base.bs;

	rc = bsa_ptn_iter_reinit(itr, BSA_POS(pos)->type);
	assert(rc == 0);
	switch (BSA_POS(pos)->type) {
	case BSA_ITER_TYPE_PTN_ID:
		if (pos->ptn_id < BPTN_ID_BEGIN ||
				pos->ptn_id >= bsa->shmem->next_ptn_id) {
			rc = EINVAL;
			goto out;
		}
		itr->ptn_id = pos->ptn_id;
		sos_key_set(id_key, &itr->ptn_id, sizeof(itr->ptn_id));
		rc = 0;
		break;
	case BSA_ITER_TYPE_PTN_FIRST_SEEN:
		rc = sos_iter_set(itr->sitr, &pos->sos_pos);
		break;
	default:
		assert(0 == "position - iterator type mismatch");
		rc = EINVAL;
	}
out:
	return rc;
}

static
bptn_iter_t bsa_ptn_iter_new(bstore_t bs)
{
	bsa_t bsa = (void*)bs;
	sos_iter_t sitr;
	bsa_ptn_iter_t itr = calloc(1, sizeof(*itr));
	if (!itr)
		goto err0;
	itr->base.bs = bs;
	itr->ptn_id = 0;
	itr->type = BSA_ITER_TYPE_PTN_ID;
	itr->sitr = NULL;
out:
	return (void*)itr;

err1:
	free(itr);
err0:
	return NULL;
}

static
void bsa_ptn_iter_free(bptn_iter_t _itr)
{
	bsa_ptn_iter_t itr = (void*)_itr;
	if (itr->sitr)
		sos_iter_free(itr->sitr);
	free(itr);
}

static
uint64_t bsa_ptn_iter_card(bptn_iter_t _itr)
{
	bsa_ptn_iter_t itr = (void*)_itr;
	bsa_t bsa = (void*)itr->base.bs;
	return bsa->shmem->next_ptn_id - BPTN_ID_BEGIN;
}

static
bptn_t bsa_ptn_iter_obj(bptn_iter_t _itr);

static
bptn_t bsa_ptn_iter_first(bptn_iter_t _itr);

/*
 * Find first pattern (ordered by first-seen) that the first-seen is greater
 * than start.
 */
static
bptn_t bsa_ptn_iter_find(bptn_iter_t _itr, time_t start)
{
	int rc;
	if (!start) {
		rc = bsa_ptn_iter_reinit((void*)_itr, BSA_ITER_TYPE_PTN_ID);
		return bsa_ptn_iter_first(_itr);
	}
	/* else, use `first_seen` iterator */
	bsa_ptn_iter_t itr = (void*)_itr;
	bsa_t bsa = (void*)itr->base.bs;
	SOS_KEY(ts_key);
	struct sos_timestamp_s sos_ts;
	sos_obj_t obj;
	rc = bsa_ptn_iter_reinit((void*)_itr, BSA_ITER_TYPE_PTN_FIRST_SEEN);
	if (rc)
		return NULL;
	sos_ts.secs = start;
	sos_ts.usecs = 0;
	sos_key_set(ts_key, &sos_ts, sizeof(sos_ts));
	rc = sos_iter_sup(itr->sitr, ts_key);
	if (rc)
		return NULL;
	return bsa_ptn_iter_obj(_itr);
}

static
bptn_t bsa_ptn_iter_obj(bptn_iter_t _itr)
{
	bsa_ptn_iter_t itr = (void*)_itr;
	bsa_t bsa = (void*)itr->base.bs;
	sos_obj_t obj;
	bptn_t ptn;
	switch (itr->type) {
	case BSA_ITER_TYPE_PTN_FIRST_SEEN:
		obj = sos_iter_obj(itr->sitr);
		assert(obj);
		ptn =  __bsa_make_ptn(bsa, obj);
		sos_obj_put(obj);
		return ptn;
	case BSA_ITER_TYPE_PTN_ID:
		return bsa_ptn_find(itr->base.bs, itr->ptn_id);
	default:
		errno = EINVAL;
	}
	return NULL;
}

static
bptn_t bsa_ptn_iter_next(bptn_iter_t _itr)
{
	bsa_ptn_iter_t itr = (void*)_itr;
	bsa_t bsa = (void*)itr->base.bs;
	bptn_t ptn;
	int rc;
	sos_obj_t obj;
	switch (itr->type) {
	case BSA_ITER_TYPE_PTN_FIRST_SEEN:
		rc = sos_iter_next(itr->sitr);
		if (rc)
			return NULL;
		obj = sos_iter_obj(itr->sitr);
		assert(obj);
		ptn =  __bsa_make_ptn(bsa, obj);
		sos_obj_put(obj);
		break;
	case BSA_ITER_TYPE_PTN_ID:
		if (itr->ptn_id >= bsa->shmem->next_ptn_id)
			return NULL;
		itr->ptn_id++;
		ptn = bsa_ptn_find(itr->base.bs, itr->ptn_id);
		break;
	default:
		errno = EINVAL;
		ptn = NULL;
	}
	return ptn;
}

static
bptn_t bsa_ptn_iter_prev(bptn_iter_t _itr)
{
	bsa_ptn_iter_t itr = (void*)_itr;
	bsa_t bsa = (void*)itr->base.bs;
	int rc;
	sos_obj_t obj;
	bptn_t ptn;
	switch (itr->type) {
	case BSA_ITER_TYPE_PTN_FIRST_SEEN:
		rc = sos_iter_prev(itr->sitr);
		if (rc)
			return NULL;
		obj = sos_iter_obj(itr->sitr);
		assert(obj);
		ptn =  __bsa_make_ptn(bsa, obj);
		sos_obj_put(obj);
		break;
	case BSA_ITER_TYPE_PTN_ID:
		if (itr->ptn_id <= BPTN_ID_BEGIN)
			return NULL;
		itr->ptn_id--;
		ptn = bsa_ptn_find(itr->base.bs, itr->ptn_id);
		break;
	default:
		errno = EINVAL;
		ptn = NULL;
	}
	return ptn;
}

static
bptn_t bsa_ptn_iter_first(bptn_iter_t _itr)
{
	bsa_ptn_iter_t itr = (void*)_itr;
	bsa_tryupdate((bsa_t)itr->base.bs);
	itr->ptn_id = BPTN_ID_BEGIN;
	if (itr->sitr) {
		sos_iter_free(itr->sitr);
		itr->sitr = NULL;
	}
	return bsa_ptn_find(itr->base.bs, itr->ptn_id);
}

static
bptn_t bsa_ptn_iter_last(bptn_iter_t _itr)
{
	bsa_ptn_iter_t itr = (void*)_itr;
	bsa_t bsa = (void*)itr->base.bs;
	bsa_tryupdate((bsa_t)itr->base.bs);
	itr->ptn_id = bsa->shmem->next_ptn_id - 1;
	if (itr->sitr) {
		sos_iter_free(itr->sitr);
		itr->sitr = NULL;
	}
	return bsa_ptn_find(itr->base.bs, itr->ptn_id);
}

static
bstore_iter_pos_t bsa_ptn_tkn_iter_pos(bptn_tkn_iter_t _itr)
{
	bsa_ptn_tkn_iter_t itr = (void*)_itr;
	sos_pos_t sos_pos;
	bsa_ptn_tkn_iter_pos_t pos;
	int rc;
	size_t sz;

	sos_pos = sos_iter_pos(itr->sitr);
	if (!sos_pos)
		return NULL;
	sz = sizeof(*pos) + sos_pos->data_len;
	pos = calloc(1, sz);
	if (!pos) {
		free(sos_pos);
		return NULL;
	}
	BSA_POS(pos)->type = BSA_ITER_TYPE_PTN_TKN;
	BS_POS(pos)->data_len = sz - sizeof(struct bstore_iter_pos_s);
	memcpy(&pos->sos_pos, sos_pos, sos_pos_sz(sos_pos));
	free(sos_pos);
	return BS_POS(pos);
}

static
int bsa_ptn_tkn_iter_pos_set(bptn_tkn_iter_t _itr, bstore_iter_pos_t _pos)
{
	int rc;
	sos_key_t key;
	ptn_pos_tkn_t kv;
	bsa_ptn_tkn_iter_t itr = (void*)_itr;
	bsa_ptn_tkn_iter_pos_t pos = (void*)_pos;
	if (BSA_POS(pos)->type != BSA_ITER_TYPE_PTN_TKN) {
		assert(0 == "position - iterator type mismatch");
		return EINVAL;
	}
	rc = sos_iter_set(itr->sitr, &pos->sos_pos);
	if (rc)
		return rc;
	key = sos_iter_key(itr->sitr);
	if (!key)
		return errno;
	kv = (void*)sos_key_value(key);
	itr->kv = *kv;
	sos_key_put(key);
	return 0;
}

static
bptn_tkn_iter_t bsa_ptn_tkn_iter_new(bstore_t bs)
{
	bsa_t bsa = (void*)bs;
	bsa_ptn_tkn_iter_t itr = calloc(1, sizeof(*itr));
	if (!itr)
		return NULL;
	itr->base.bs = bs;
	itr->sitr = sos_attr_iter_new(bsa->ptn_pos_tkn_key_attr);
	if (!itr->sitr) {
		free(itr);
		return NULL;
	}
	return &itr->base;
}

static
void bsa_ptn_tkn_iter_free(bptn_tkn_iter_t i)
{
	bsa_ptn_tkn_iter_t itr = (void*)i;
	if (itr->sitr)
		sos_iter_free(itr->sitr);
	free(itr);
}

static
uint64_t bsa_ptn_tkn_iter_card(bptn_tkn_iter_t i)
{
	/* TODO XXX Is this correct? */
	return sos_iter_card(((bsa_ptn_tkn_iter_t)i)->sitr);
}

static
btkn_t bsa_ptn_tkn_iter_find(bptn_tkn_iter_t _itr, bptn_id_t ptn_id, uint64_t pos)
{
	int rc;
	bsa_ptn_tkn_iter_t itr = (void*)_itr;
	SOS_KEY(key);

	itr->kv.ptn_id = htobe64(ptn_id);
	itr->kv.pos = htobe64(pos);
	itr->kv.tkn_id = 0;

	sos_key_set(key, &itr->kv, sizeof(itr->kv));

	rc = sos_iter_sup(itr->sitr, key);
	if (rc)
		return NULL;
	return bsa_ptn_tkn_iter_obj(_itr);
}

static
btkn_t bsa_ptn_tkn_iter_obj(bptn_tkn_iter_t _itr)
{
	bsa_ptn_tkn_iter_t itr = (void*)_itr;
	sos_key_t key;
	ptn_pos_tkn_t kv;
	btkn_t tkn = NULL;
	key = sos_iter_key(itr->sitr);
	if (!key)
		return NULL;
	kv = (void*)sos_key_value(key);
	if (kv->ptn_id != itr->kv.ptn_id || kv->pos != itr->kv.pos)
		goto out;
	tkn = bsa_ptn_tkn_find(itr->base.bs,
					be64toh(kv->ptn_id),
					be64toh(kv->pos),
					be64toh(kv->tkn_id));
out:
	sos_key_put(key);
	return tkn;
}

static
btkn_t bsa_ptn_tkn_iter_next(bptn_tkn_iter_t _itr)
{
	bsa_ptn_tkn_iter_t itr = (void*)_itr;
	sos_obj_t obj;
	int rc;
	rc = sos_iter_next(itr->sitr);
	if (rc)
		return NULL;
	return bsa_ptn_tkn_iter_obj(_itr);
}

static
btkn_t bsa_ptn_tkn_iter_prev(bptn_tkn_iter_t _itr)
{
	bsa_ptn_tkn_iter_t itr = (void*)_itr;
	sos_obj_t obj;
	int rc;
	rc = sos_iter_prev(itr->sitr);
	if (rc)
		return NULL;
	return bsa_ptn_tkn_iter_obj(_itr);
}

/*
 * Return the type id for a token type name
 */
static
btkn_type_t bsa_tkn_type_get(bstore_t bs, const char *typ_name, size_t name_len)
{
	char *type_name;
	btkn_t btkn;
	btkn_type_t type_id;
	bsa_t bsa = (bsa_t)bs;

	name_len = name_len + 3;
	type_name = malloc(name_len);
	if (!type_name) {
		errno = ENOMEM;
		return 0;
	}
	snprintf(type_name, name_len, "_%s_", typ_name);
	btkn = bsa_tkn_find_by_name(bs, type_name, name_len-1);
	if (!btkn) {
		errno = ENOENT;
		type_id = 0;
		goto out;
	}
	type_id = btkn->tkn_id;
	btkn_free(btkn);
out:
	free(type_name);
	return type_id;
}

static
int bsa_tkn_hist_update(bstore_t bs, time_t sec, time_t bin_width,
		       btkn_id_t tkn_id)
{
	berr("bstore_agg is a read-only store.");
	return ENOSYS;
}

static
btkn_hist_iter_t bsa_tkn_hist_iter_new(bstore_t bs)
{
	return (void*) bsa_hist_iter_new((void*)bs, BSA_ITER_TYPE_TKN_HIST);
}

static
int bsa_ptn_hist_update(bstore_t bs,
		       bptn_id_t ptn_id, bcomp_id_t comp_id,
		       time_t secs, time_t bin_width)
{
	berr("bstore_agg is a read-only store.");
	return ENOSYS;
}

static
int bsa_ptn_tkn_add(bstore_t bs,
		   bptn_id_t ptn_id, uint64_t tkn_pos, btkn_id_t tkn_id)
{
	berr("bstore_agg is a read-only store.");
	return ENOSYS;
}


static
btkn_t bsa_ptn_tkn_find(bstore_t bs,
		       bptn_id_t ptn_id, uint64_t tkn_pos, btkn_id_t tkn_id)
{
	bsa_t bsa = (void*)bs;
	btkn_t tkn;
	btkn_t bs_tkn;
	btkn_id_t bs_tkn_id;
	bptn_id_t bs_ptn_id;
	bstore_entry_t bent;
	int rc;

	tkn = bsa_tkn_find_by_id(bs, tkn_id);
	if (!tkn)
		goto out;

	tkn->tkn_count = 0;

	TAILQ_FOREACH(bent, &bsa->bs_tq, link) {
		bs_ptn_id = __ptn_id_xlate(ptn_id, (void*)bsa, bent->bs);
		bs_tkn_id = __tkn_id_xlate(tkn_id, (void*)bsa, bent->bs);
		bs_tkn = bstore_ptn_tkn_find(bent->bs, bs_ptn_id, tkn_pos,
								bs_tkn_id);
		if (!bs_tkn)
			continue;
		tkn->tkn_count += bs_tkn->tkn_count;
		tkn->tkn_type_mask |= bs_tkn->tkn_type_mask;
		btkn_free(bs_tkn);
	}

	if (!tkn->tkn_count) {
		btkn_free(tkn);
		tkn = NULL;
	}
out:
	return tkn;
}

static
bptn_hist_iter_t bsa_ptn_hist_iter_new(bstore_t bs)
{
	return (void*)bsa_hist_iter_new((void*)bs, BSA_ITER_TYPE_PTN_HIST);
}

int bsa_comp_hist_fwd_key_cmp(const struct bcomp_hist_s *a,
			      const struct bcomp_hist_s *b)
{
	/* NULL is always the greatest so that it sink to the bottom. */
	if (!a) {
		if (!b)
			return 0;
		return 1;
	}
	if (!b)
		return -1;
	if (a->bin_width < b->bin_width)
		return -1;
	if (a->bin_width > b->bin_width)
		return 1;
	if (a->time < b->time)
		return -1;
	if (a->time > b->time)
		return 1;
	if (a->comp_id < b->comp_id)
		return -1;
	if (a->comp_id > b->comp_id)
		return 1;
	if (a->ptn_id < b->ptn_id)
		return -1;
	if (a->ptn_id > b->ptn_id)
		return 1;
	return 0;
}

int bsa_comp_hist_bwd_key_cmp(const struct bcomp_hist_s *a,
			      const struct bcomp_hist_s *b)
{
	/* NULL is always the greatest so that it sink to the bottom. */
	if (!a) {
		if (!b)
			return 0;
		return 1;
	}
	if (!b)
		return -1;
	if (a->bin_width > b->bin_width)
		return -1;
	if (a->bin_width < b->bin_width)
		return 1;
	if (a->time > b->time)
		return -1;
	if (a->time < b->time)
		return 1;
	if (a->comp_id > b->comp_id)
		return -1;
	if (a->comp_id < b->comp_id)
		return 1;
	if (a->ptn_id < b->ptn_id)
		return -1;
	if (a->ptn_id > b->ptn_id)
		return 1;
	return 0;
}

void bsa_comp_hist_merge(bcomp_hist_t a, bcomp_hist_t b)
{
	a->msg_count += b->msg_count;
}

bcomp_hist_t bsa_comp_hist_copy(bcomp_hist_t a, bcomp_hist_t b)
{
	return memcpy(b, a, sizeof(*a));
}

uint32_t bsa_comp_hist_time(bcomp_hist_t a)
{
	return a->time;
}

static
bcomp_hist_iter_t bsa_comp_hist_iter_new(bstore_t bs)
{
	return (void*)bsa_hist_iter_new((void*)bs, BSA_ITER_TYPE_COMP_HIST);
}

bstore_t bsa_find_bstore(bsa_t bsa, const char *path)
{
	bstore_entry_t ent;
	TAILQ_FOREACH(ent, &bsa->bs_tq, link) {
		if (strcmp(path, ent->bs->path) == 0)
			return ent->bs;
	}
	return NULL;
}

static struct bstore_plugin_s plugin = {
	.open = bsa_open,
	.close = bsa_close,

	.tkn_type_get = bsa_tkn_type_get,

	.tkn_add = bsa_tkn_add,
	.tkn_add_with_id = bsa_tkn_add_with_id,
	.tkn_find_by_id = bsa_tkn_find_by_id,
	.tkn_find_by_name = bsa_tkn_find_by_name,

	.tkn_iter_pos = bsa_tkn_iter_pos,
	.tkn_iter_pos_set = bsa_tkn_iter_pos_set,
	.tkn_iter_new = bsa_tkn_iter_new,
	.tkn_iter_free = bsa_tkn_iter_free,
	.tkn_iter_card = bsa_tkn_iter_card,
	.tkn_iter_first = bsa_tkn_iter_first,
	.tkn_iter_obj = bsa_tkn_iter_obj,
	.tkn_iter_next = bsa_tkn_iter_next,
	.tkn_iter_prev = bsa_tkn_iter_prev,
	.tkn_iter_last = bsa_tkn_iter_last,

	.msg_add = bsa_msg_add,
	.msg_iter_pos = bsa_msg_iter_pos,
	.msg_iter_pos_set = bsa_msg_iter_pos_set,
	.msg_iter_new = bsa_msg_iter_new,
	.msg_iter_free = bsa_msg_iter_free,
	.msg_iter_card = bsa_msg_iter_card,
	.msg_iter_find = bsa_msg_iter_find,
	.msg_iter_first = bsa_msg_iter_first,
	.msg_iter_last = bsa_msg_iter_last,
	.msg_iter_obj = bsa_msg_iter_obj,
	.msg_iter_next = bsa_msg_iter_next,
	.msg_iter_prev = bsa_msg_iter_prev,

	.ptn_add = bsa_ptn_add,
	.ptn_find = bsa_ptn_find,
	.ptn_find_by_ptnstr = bsa_ptn_find_by_ptnstr,
	.ptn_iter_pos = bsa_ptn_iter_pos,
	.ptn_iter_pos_set = bsa_ptn_iter_pos_set,
	.ptn_iter_new = bsa_ptn_iter_new,
	.ptn_iter_free = bsa_ptn_iter_free,
	.ptn_iter_card = bsa_ptn_iter_card,
	.ptn_iter_find = bsa_ptn_iter_find,
	.ptn_iter_first = bsa_ptn_iter_first,
	.ptn_iter_last = bsa_ptn_iter_last,
	.ptn_iter_obj = bsa_ptn_iter_obj,
	.ptn_iter_next = bsa_ptn_iter_next,
	.ptn_iter_prev = bsa_ptn_iter_prev,

	.ptn_tkn_add = bsa_ptn_tkn_add,
	.ptn_tkn_find = bsa_ptn_tkn_find,

	.ptn_tkn_iter_pos = bsa_ptn_tkn_iter_pos,
	.ptn_tkn_iter_pos_set = bsa_ptn_tkn_iter_pos_set,
	.ptn_tkn_iter_new = bsa_ptn_tkn_iter_new,
	.ptn_tkn_iter_free = bsa_ptn_tkn_iter_free,
	.ptn_tkn_iter_card = bsa_ptn_tkn_iter_card,
	.ptn_tkn_iter_find = bsa_ptn_tkn_iter_find,
	.ptn_tkn_iter_obj = bsa_ptn_tkn_iter_obj,
	.ptn_tkn_iter_next = bsa_ptn_tkn_iter_next,
	.ptn_tkn_iter_prev = bsa_ptn_tkn_iter_prev,

	.tkn_hist_update = bsa_tkn_hist_update,
	.tkn_hist_iter_pos = (void*)bsa_hist_iter_pos,
	.tkn_hist_iter_pos_set = (void*)bsa_hist_iter_pos_set,
	.tkn_hist_iter_new = bsa_tkn_hist_iter_new,
	.tkn_hist_iter_free = (void*)bsa_hist_iter_free,

	.tkn_hist_iter_obj = (void*)bsa_hist_iter_obj,
	.tkn_hist_iter_next = (void*)bsa_hist_iter_next,
	.tkn_hist_iter_first = (void*)bsa_hist_iter_first,
	.tkn_hist_iter_find = (void*)bsa_hist_iter_first,
	.tkn_hist_iter_last = (void*)bsa_hist_iter_last,

	.ptn_hist_update = bsa_ptn_hist_update,
	.ptn_hist_iter_pos = (void*)bsa_hist_iter_pos,
	.ptn_hist_iter_pos_set = (void*)bsa_hist_iter_pos_set,
	.ptn_hist_iter_new = bsa_ptn_hist_iter_new,
	.ptn_hist_iter_free = (void*)bsa_hist_iter_free,

	.ptn_hist_iter_obj = (void*)bsa_hist_iter_obj,
	.ptn_hist_iter_next = (void*)bsa_hist_iter_next,
	.ptn_hist_iter_first = (void*)bsa_hist_iter_first,
	.ptn_hist_iter_find = (void*)bsa_hist_iter_first,
	.ptn_hist_iter_last = (void*)bsa_hist_iter_last,

	.comp_hist_iter_pos = (void*)bsa_hist_iter_pos,
	.comp_hist_iter_pos_set = (void*)bsa_hist_iter_pos_set,
	.comp_hist_iter_new = bsa_comp_hist_iter_new,
	.comp_hist_iter_free = (void*)bsa_hist_iter_free,

	.comp_hist_iter_obj = (void*)bsa_hist_iter_obj,
	.comp_hist_iter_next = (void*)bsa_hist_iter_next,
	.comp_hist_iter_first = (void*)bsa_hist_iter_first,
	.comp_hist_iter_find = (void*)bsa_hist_iter_first,
	.comp_hist_iter_last = (void*)bsa_hist_iter_last,
};

bstore_plugin_t init_store(void)
{
	return &plugin;
}

/**
 * \page bstore_agg bstore_agg
 *
 *
 * \section SYNOPSIS SYNOPSIS
 * C-API: \b bstore_open (<b>\"bstore_agg\"</b>, \b bsa_config_file, flags, mode);
 *
 * CLI: \b balerd -S \b bstore_agg -s \b bsa_config_file (other_args)
 *
 * CLI: \b cquery -S \b bstore_agg -s \b bsa_config_file (other_args)
 *
 *
 * \section DESCRIPTION DESCRIPTION
 *
 * \b bstore_agg is an aggregation point of multiple \c bstore's and export the
 * aggregated information through \c bstore interface. The \c bsa_config_file is
 * used in the place of usual bstore path argument position in order to pass
 * information needed by \c bstore_agg.
 *
 * The information needed by \c bstore_agg are 1) path to SOS database that will
 * be used by bstore_agg to store its information, and 2) a list of other
 * \c bstore's and their paths.
 *
 * Please refer to \ref CONFIGURATION_FILE section for more information about \c
 * bsa_config_file.
 *
 *
 * \section CONFIGURATION_FILE CONFIGURATION FILE
 *
 * \code
 * sos: /path/to/aggregated/sos/database
 * update_threads: 4
 * bstore: /path/to/bstore0
 * bstore: /path/to/bstore1
 * bstore: /path/to/bstore2
 * ...
 * \endcode
 *
 *
 * \section NOTE NOTE
 *
 * \subsection IUM internal unified maps (tokens and patterns)
 * An intenal unified map is an internal mapping (STR \<==\> ID), for tokens or
 * patterns, that collectively aggregate related information from sub-bstore's.
 *
 *
 * \subsection IUM_TKN Unified token map
 * A token (or tokens) not existed in the unified token map, but existed in the
 * token map of a bstore, will be inserted into the unified token map when a new
 * token is found by:
 *
 * - application calling \c tkn_find_by_name() interface, and \c bstore_agg
 *   found the token in at least one of the bstore.
 * - application calling \c msg_iter_*() interface, and \c bstore_agg encounter
 *   a new noken.
 * - \c bsa_tryupdate() is called.
 *
 * \subsection IUM_PTN Unified pattern map.
 * Similarly to the \ref IUM_TKN, but a lot simpler, a new pattern will be added
 * when \c bstore_agg encounter a new pattern by:
 *
 * - \c bsa_tryupdate() is called.
 * - application calling \c msg_iter_*() interface, and \c bstore_agg encounter
 *   a new pattern.
 *
 * \subsection IUM_UPDATE Unified pattern maps update.
 *
 * \c bsa_tryupdate() is the function that try to hold a bsa lock and update the
 * unified maps. If it cannot acquire the lock, the function returns immediately
 * as the other process (or thread) holding the lock is updating the store.
 *
 * \c bsa_tryupdate() is called:
 * - at bstore_open()
 * - at ptn_iter_first()
 * - at ptn_iter_last()
 * - periodically by a dedicated updater thread (if specified in config file).
 *
 * The update routine needs to go through entire pattern and token maps of all
 * sub-bstores because currently there is no way of getting just the updated
 * ones. Even though \c bstore_agg wants to keep the last known max ID of a map
 * in a sub-bstore, \c bstore_agg cannot expect that the new token ID will be
 * consecutive. Hence, it has to go through the entire store :(
 *
 */