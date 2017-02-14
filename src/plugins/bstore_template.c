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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>
#include <assert.h>
#include "baler/bstore.h"

typedef struct bstore_EXT_s {
	struct bstore_s base;
	/* extend the structure here */
} *bstore_EXT_t;

typedef struct bstore_EXT_iter_s {
	struct bstore_iter_s base;
	/* extend the structure here */
} *bstore_EXT_iter_t;

typedef struct bstore_EXT_iter_pos_s {
	/* bstore_iter_pos_t is (void *) */
} *bstore_EXT_iter_pos_t;

static
bstore_t EXT_open(struct bstore_plugin_s *plugin, const char *path,
		 int flags, int o_mode);
static
void EXT_close(bstore_t bs);

/*
 * If the token is not present in the store, add it. In either
 * case, return it's tkn_id
 */
static
btkn_id_t EXT_tkn_add(bstore_t bs, btkn_t tkn);

/*
 * Add a token with an id. The token id cannot already exist.
 */
static
int EXT_tkn_add_with_id(bstore_t bs, btkn_t tkn);

static
btkn_t EXT_tkn_find_by_id(bstore_t bs, btkn_id_t tkn_id);

static
btkn_t EXT_tkn_find_by_name(bstore_t bs, const char *name, size_t name_len);

static
bstore_iter_pos_t EXT_tkn_iter_pos(btkn_iter_t);

static
int EXT_tkn_iter_pos_set(btkn_iter_t, bstore_iter_pos_t);

static
btkn_iter_t EXT_tkn_iter_new(bstore_t bs);

static
void EXT_tkn_iter_free(btkn_iter_t i);

static
uint64_t EXT_tkn_iter_card(btkn_iter_t i);

static
btkn_t EXT_tkn_iter_first(btkn_iter_t iter);

static
btkn_t EXT_tkn_iter_obj(btkn_iter_t iter);

static
btkn_t EXT_tkn_iter_next(btkn_iter_t iter);

static
int EXT_msg_add(bstore_t bs, struct timeval *tv, bmsg_t msg);

static
bstore_iter_pos_t EXT_msg_iter_pos(bmsg_iter_t);

static
int EXT_msg_iter_pos_set(bmsg_iter_t, bstore_iter_pos_t);

static
bmsg_iter_t EXT_msg_iter_new(bstore_t bs);

static
void EXT_msg_iter_free(bmsg_iter_t i);

static
uint64_t EXT_msg_iter_card(bmsg_iter_t i);

static
bmsg_t EXT_msg_iter_find(bmsg_iter_t i,
			time_t start, bptn_id_t ptn_id, bcomp_id_t comp_id,
			bmsg_cmp_fn_t cmp_fn, void *ctxt);

static
bmsg_t EXT_msg_iter_obj(bmsg_iter_t i);

static
bmsg_t EXT_msg_iter_next(bmsg_iter_t i);

static
bmsg_t EXT_msg_iter_prev(bmsg_iter_t i);

static
bmsg_t EXT_msg_iter_first(bmsg_iter_t i);

static
bmsg_t EXT_msg_iter_last(bmsg_iter_t i);

static
bptn_id_t EXT_ptn_add(bstore_t bs, struct timeval *tv, bstr_t ptn);

static
bptn_t EXT_ptn_find(bstore_t bs, bptn_id_t ptn_id);

static
int EXT_ptn_find_by_ptnstr(bstore_t bs, bptn_t ptn);

static
bstore_iter_pos_t EXT_ptn_iter_pos(bptn_iter_t);

static
int EXT_ptn_iter_pos_set(bptn_iter_t, bstore_iter_pos_t);

static
bptn_iter_t EXT_ptn_iter_new(bstore_t bs);

static
void EXT_ptn_iter_free(bptn_iter_t i);

static
uint64_t EXT_ptn_iter_card(bptn_iter_t i);

static
bptn_t EXT_ptn_iter_find(bptn_iter_t iter, time_t start);

static
bptn_t EXT_ptn_iter_obj(bptn_iter_t iter);

static
bptn_t EXT_ptn_iter_next(bptn_iter_t iter);

static
bptn_t EXT_ptn_iter_prev(bptn_iter_t iter);

static
bptn_t EXT_ptn_iter_first(bptn_iter_t iter);

static
bptn_t EXT_ptn_iter_last(bptn_iter_t iter);

static
bstore_iter_pos_t EXT_ptn_tkn_iter_pos(bptn_tkn_iter_t);

static
int EXT_ptn_tkn_iter_pos_set(bptn_tkn_iter_t, bstore_iter_pos_t);

static
bptn_tkn_iter_t EXT_ptn_tkn_iter_new(bstore_t bs);

static
void EXT_ptn_tkn_iter_free(bptn_tkn_iter_t i);

static
uint64_t EXT_ptn_tkn_iter_card(bptn_tkn_iter_t i);

static
btkn_t EXT_ptn_tkn_iter_find(bptn_tkn_iter_t iter, bptn_id_t ptn_id, uint64_t pos);

static
btkn_t EXT_ptn_tkn_iter_obj(bptn_tkn_iter_t iter);

static
btkn_t EXT_ptn_tkn_iter_next(bptn_tkn_iter_t iter);

/*
 * Return the type id for a token type name
 */
static
btkn_type_t EXT_tkn_type_get(bstore_t bs, const char *name, size_t name_len);

static
int EXT_tkn_hist_update(bstore_t bs, time_t sec, time_t bin_width,
		       btkn_id_t tkn_id);
static
bstore_iter_pos_t EXT_tkn_hist_iter_pos(btkn_hist_iter_t);
static
int EXT_tkn_hist_iter_pos_set(btkn_hist_iter_t, bstore_iter_pos_t);
static
btkn_hist_iter_t EXT_tkn_hist_iter_new(bstore_t bs);
static
void EXT_tkn_hist_iter_free(btkn_hist_iter_t iter);
static
btkn_hist_t EXT_tkn_hist_iter_find(btkn_hist_iter_t iter, btkn_hist_t tkn_h);
static
btkn_hist_t EXT_tkn_hist_iter_obj(btkn_hist_iter_t iter, btkn_hist_t tkn_h);
static
btkn_hist_t EXT_tkn_hist_iter_next(btkn_hist_iter_t iter, btkn_hist_t tkn_h);
static
btkn_hist_t EXT_tkn_hist_iter_prev(btkn_hist_iter_t iter, btkn_hist_t tkn_h);
static
btkn_hist_t EXT_tkn_hist_iter_first(btkn_hist_iter_t iter, btkn_hist_t tkn_h);
static
btkn_hist_t EXT_tkn_hist_iter_last(btkn_hist_iter_t iter, btkn_hist_t tkn_h);

static
int EXT_ptn_hist_update(bstore_t bs,
		       bptn_id_t ptn_id, bcomp_id_t comp_id,
		       time_t secs, time_t bin_width);
static
int EXT_ptn_tkn_add(bstore_t bs,
		   bptn_id_t ptn_id, uint64_t tkn_pos, btkn_id_t tkn_id);

static
btkn_t EXT_ptn_tkn_find(bstore_t bs,
		       bptn_id_t ptn_id, uint64_t tkn_pos, btkn_id_t tkn_id);

static
bstore_iter_pos_t EXT_ptn_hist_iter_pos(bptn_hist_iter_t);

static
int EXT_ptn_hist_iter_pos_set(bptn_hist_iter_t, bstore_iter_pos_t);

static
bptn_hist_iter_t EXT_ptn_hist_iter_new(bstore_t bs);

static
void EXT_ptn_hist_iter_free(bptn_hist_iter_t iter);

static
bptn_hist_t EXT_ptn_hist_iter_find(bptn_hist_iter_t iter, bptn_hist_t ptn_h);

static
bptn_hist_t EXT_ptn_hist_iter_obj(bptn_hist_iter_t iter, bptn_hist_t ptn_h);

static
bptn_hist_t EXT_ptn_hist_iter_next(bptn_hist_iter_t iter, bptn_hist_t ptn_h);

static
bptn_hist_t EXT_ptn_hist_iter_prev(bptn_hist_iter_t iter, bptn_hist_t ptn_h);

static
bptn_hist_t EXT_ptn_hist_iter_first(bptn_hist_iter_t iter, bptn_hist_t ptn_h);

static
bptn_hist_t EXT_ptn_hist_iter_last(bptn_hist_iter_t iter, bptn_hist_t ptn_h);

static
bstore_iter_pos_t EXT_comp_hist_iter_pos(bcomp_hist_iter_t);

static
int EXT_comp_hist_iter_pos_set(bcomp_hist_iter_t, bstore_iter_pos_t);

static
bcomp_hist_iter_t EXT_comp_hist_iter_new(bstore_t bs);

static
void EXT_comp_hist_iter_free(bcomp_hist_iter_t iter);

static
bcomp_hist_t EXT_comp_hist_iter_find(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);

static
bcomp_hist_t EXT_comp_hist_iter_obj(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);

static
bcomp_hist_t EXT_comp_hist_iter_next(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);

static
bcomp_hist_t EXT_comp_hist_iter_prev(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);

static
bcomp_hist_t EXT_comp_hist_iter_first(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);

static
bcomp_hist_t EXT_comp_hist_iter_last(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);

static
const char *EXT_iter_pos_to_str(bstore_iter_t, bstore_iter_pos_t);

static
bstore_iter_pos_t EXT_iter_pos_from_str(bstore_iter_t, const char *);

static
void EXT_iter_pos_free(bstore_iter_t, bstore_iter_pos_t);

static struct bstore_plugin_s plugin = {
	.open = EXT_open,
	.close = EXT_close,

	.tkn_type_get = EXT_tkn_type_get,

	.tkn_add = EXT_tkn_add,
	.tkn_add_with_id = EXT_tkn_add_with_id,
	.tkn_find_by_id = EXT_tkn_find_by_id,
	.tkn_find_by_name = EXT_tkn_find_by_name,

	.tkn_iter_pos = EXT_tkn_iter_pos,
	.tkn_iter_pos_set = EXT_tkn_iter_pos_set,
	.tkn_iter_new = EXT_tkn_iter_new,
	.tkn_iter_free = EXT_tkn_iter_free,
	.tkn_iter_card = EXT_tkn_iter_card,
	.tkn_iter_first = EXT_tkn_iter_first,
	.tkn_iter_obj = EXT_tkn_iter_obj,
	.tkn_iter_next = EXT_tkn_iter_next,

	.msg_add = EXT_msg_add,
	.msg_iter_pos = EXT_msg_iter_pos,
	.msg_iter_pos_set = EXT_msg_iter_pos_set,
	.msg_iter_new = EXT_msg_iter_new,
	.msg_iter_free = EXT_msg_iter_free,
	.msg_iter_card = EXT_msg_iter_card,
	.msg_iter_find = EXT_msg_iter_find,
	.msg_iter_first = EXT_msg_iter_first,
	.msg_iter_last = EXT_msg_iter_last,
	.msg_iter_obj = EXT_msg_iter_obj,
	.msg_iter_next = EXT_msg_iter_next,
	.msg_iter_prev = EXT_msg_iter_prev,

	.ptn_add = EXT_ptn_add,
	.ptn_find = EXT_ptn_find,
	.ptn_find_by_ptnstr = EXT_ptn_find_by_ptnstr,
	.ptn_iter_pos = EXT_ptn_iter_pos,
	.ptn_iter_pos_set = EXT_ptn_iter_pos_set,
	.ptn_iter_new = EXT_ptn_iter_new,
	.ptn_iter_free = EXT_ptn_iter_free,
	.ptn_iter_card = EXT_ptn_iter_card,
	.ptn_iter_find = EXT_ptn_iter_find,
	.ptn_iter_first = EXT_ptn_iter_first,
	.ptn_iter_last = EXT_ptn_iter_last,
	.ptn_iter_obj = EXT_ptn_iter_obj,
	.ptn_iter_next = EXT_ptn_iter_next,
	.ptn_iter_prev = EXT_ptn_iter_prev,

	.ptn_tkn_iter_pos = EXT_ptn_tkn_iter_pos,
	.ptn_tkn_iter_pos_set = EXT_ptn_tkn_iter_pos_set,
	.ptn_tkn_iter_new = EXT_ptn_tkn_iter_new,
	.ptn_tkn_iter_free = EXT_ptn_tkn_iter_free,
	.ptn_tkn_iter_card = EXT_ptn_tkn_iter_card,
	.ptn_tkn_iter_find = EXT_ptn_tkn_iter_find,
	.ptn_tkn_iter_obj = EXT_ptn_tkn_iter_obj,
	.ptn_tkn_iter_next = EXT_ptn_tkn_iter_next,

	.tkn_hist_update = EXT_tkn_hist_update,
	.tkn_hist_iter_pos = EXT_tkn_hist_iter_pos,
	.tkn_hist_iter_pos_set = EXT_tkn_hist_iter_pos_set,
	.tkn_hist_iter_new = EXT_tkn_hist_iter_new,
	.tkn_hist_iter_free = EXT_tkn_hist_iter_free,

	.tkn_hist_iter_obj = EXT_tkn_hist_iter_obj,
	.tkn_hist_iter_next = EXT_tkn_hist_iter_next,
	.tkn_hist_iter_prev = EXT_tkn_hist_iter_prev,
	.tkn_hist_iter_first = EXT_tkn_hist_iter_find,
	.tkn_hist_iter_last = EXT_tkn_hist_iter_last,

	.ptn_hist_update = EXT_ptn_hist_update,
	.ptn_tkn_add = EXT_ptn_tkn_add,
	.ptn_tkn_find = EXT_ptn_tkn_find,
	.ptn_hist_iter_pos = EXT_ptn_hist_iter_pos,
	.ptn_hist_iter_pos_set = EXT_ptn_hist_iter_pos_set,
	.ptn_hist_iter_new = EXT_ptn_hist_iter_new,
	.ptn_hist_iter_free = EXT_ptn_hist_iter_free,

	.ptn_hist_iter_obj = EXT_ptn_hist_iter_obj,
	.ptn_hist_iter_next = EXT_ptn_hist_iter_next,
	.ptn_hist_iter_prev = EXT_ptn_hist_iter_prev,
	.ptn_hist_iter_first = EXT_ptn_hist_iter_find,
	.ptn_hist_iter_last = EXT_ptn_hist_iter_last,

	.comp_hist_iter_pos = EXT_comp_hist_iter_pos,
	.comp_hist_iter_pos_set = EXT_comp_hist_iter_pos_set,
	.comp_hist_iter_new = EXT_comp_hist_iter_new,
	.comp_hist_iter_free = EXT_comp_hist_iter_free,

	.comp_hist_iter_obj = EXT_comp_hist_iter_obj,
	.comp_hist_iter_next = EXT_comp_hist_iter_next,
	.comp_hist_iter_prev = EXT_comp_hist_iter_prev,
	.comp_hist_iter_first = EXT_comp_hist_iter_find,
	.comp_hist_iter_last = EXT_comp_hist_iter_last,

	.iter_pos_to_str = EXT_iter_pos_to_str,
	.iter_pos_from_str = EXT_iter_pos_from_str,
	.iter_pos_free = EXT_iter_pos_free,
};

bstore_plugin_t init_store(void)
{
	return &plugin;
}
