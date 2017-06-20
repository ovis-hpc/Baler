/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2017 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2017 Sandia Corporation. All rights reserved.
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
#include "bmeta.h"
#include "bhash.h"
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>

uint64_t ERR_PTN_STR[16]; /* the content is init in __bmc_init_once() */
struct bptn ERR_PTN = {.str = (void*)ERR_PTN_STR};

void bmc_list_init(struct bmc_list_s *bmc_list)
{
	bzero(bmc_list, sizeof(*bmc_list));
	TAILQ_INIT(&bmc_list->bmc_head);
	TAILQ_INIT(&bmc_list->_.ent_head);
}

static
int __bmc_list_is_clean(bmc_list_t list)
{
	if (list->_.hash)
		return 0;
	if (!TAILQ_EMPTY(&list->bmc_head))
		return 0;
	if (!TAILQ_EMPTY(&list->_.ent_head))
		return 0;
	if (list->bmc_n)
		return 0;
	if (list->_.ent_n)
		return 0;
	return 1;
}

uint64_t __primes[] = {
	1031,
	2053,
	4099,
	8209,
	16411,
	32771,
	65539
};

static
int __get_prime(uint64_t x)
{
	int i;
	for (i = 0; i < sizeof(__primes)/sizeof(*__primes); i++) {
		if (x < __primes[i])
			return __primes[i];
	}
	return __primes[i-1];
}

static inline
bmc_entry_t __bmc_entry_alloc()
{
	return calloc(1, sizeof(struct bmc_entry_s));
}

static
void __bmc_entry_free(bmc_entry_t bmc_ent)
{
	if (bmc_ent->ptn)
		bptn_free(bmc_ent->ptn);
	free(bmc_ent);
}

static inline
bmc_t __bmc_alloc()
{
	bmc_t bmc = calloc(1, sizeof(struct bmc_s));
	if (bmc) {
		TAILQ_INIT(&bmc->ent_head);
	}
	return bmc;
}

struct __bmc_ent_dist_cache {
	size_t size; /* total size in bytes */
	bptn_id_t min_id;
	bptn_id_t max_id;
	float dist[0]; /* points to dist array in data */
};

static
struct __bmc_ent_dist_cache *__bmc_ent_dist_cache_alloc(bmc_list_t list)
{
	struct __bmc_ent_dist_cache *c;
	uint64_t n = list->_.ent_n;
	size_t sz = sizeof(*c) + (n*(n-1)/2)*sizeof(c->dist[0]);

	c = mmap(0, sz, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (!c)
		return 0;
	c->size = sz;
	c->min_id = 256;
	c->max_id = list->_.ent_n + c->min_id; /* assumes contiguous IDs */
	return c;
}

static
void __bmc_ent_dist_cache_free(struct __bmc_ent_dist_cache *c)
{
	munmap(c, c->size);
}

static inline
void __bmc_free(bmc_t bmc)
{
	bmc_entry_t bmc_ent;
	while ((bmc_ent = TAILQ_FIRST(&bmc->ent_head))) {
		TAILQ_REMOVE(&bmc->ent_head, bmc_ent, link);
		__bmc_entry_free(bmc_ent);
	}
	if (bmc->meta_ptn)
		bptn_free(bmc->meta_ptn);
	free(bmc);
}

static
void __bmc_list_cleanup(bmc_list_t list)
{
	bmc_t bmc;
	bmc_entry_t bmc_ent;

	if (list->_.hash) {
		bhash_free(list->_.hash);
		list->_.hash = NULL;
	}

	if (list->_.buff) {
		free(list->_.buff);
		list->_.buff = NULL;
	}

	if (list->_.lcs_idx) {
		free(list->_.lcs_idx);
		list->_.lcs_idx = NULL;
	}

	while ((bmc = TAILQ_FIRST(&list->bmc_head))) {
		TAILQ_REMOVE(&list->bmc_head, bmc, link);
		__bmc_free(bmc);
	}
	list->bmc_n = 0;

	while ((bmc_ent = TAILQ_FIRST(&list->_.ent_head))) {
		TAILQ_REMOVE(&list->_.ent_head, bmc_ent, link);
		__bmc_entry_free(bmc_ent);
	}
	list->_.ent_n = 0;

	if (list->_.dist_cache)  {
		__bmc_ent_dist_cache_free(list->_.dist_cache);
		list->_.dist_cache = NULL;
	}
}

static
int __bmc_list_pre_compute(bstore_t bs, bmc_list_t list)
{
	int rc;
	bptn_iter_t ptn_iter = NULL;
	bptn_t ptn = NULL;
	uint64_t hash_size;
	size_t max_blen = 0;
	bmc_entry_t bmc_ent;

	if (!__bmc_list_is_clean(list)) {
		rc = EINVAL;
		goto out;
	}

	/* list of bmc_entry */
	ptn_iter = bstore_ptn_iter_new(bs);
	if (!ptn_iter) {
		rc = errno;
		goto cleanup;
	}
	rc = bstore_ptn_iter_first(ptn_iter);
	while (rc == 0) {
		ptn = bstore_ptn_iter_obj(ptn_iter);
		if (!ptn) {
			rc = errno;
			goto err;
		}
		bmc_ent = __bmc_entry_alloc();
		if (!bmc_ent) {
			bptn_free(ptn);
			goto err;
		}
		bmc_ent->ptn = ptn;
		TAILQ_INSERT_TAIL(&list->_.ent_head, bmc_ent, link);
		list->_.ent_n++;
		max_blen = BMAX(max_blen, ptn->str->blen);
		rc = bstore_ptn_iter_next(ptn_iter);
	}

	/* buff for calculating edit distance + lcs back trace */
	list->_.buffsz = BMAX(16*1024*1024, 2*max_blen);
	list->_.buff = malloc(list->_.buffsz);
	if (!list->_.buff)
		goto err;

	/* lcs idx */
	list->_.lcs_idx_len = max_blen/sizeof(btkn_id_t);
	list->_.lcs_idx = malloc(sizeof(list->_.lcs_idx[0])
							* list->_.lcs_idx_len);
	if (!list->_.lcs_idx)
		goto err;

	/* hash */
	hash_size = __get_prime(list->_.ent_n);
	list->_.hash = bhash_new(hash_size, 0, NULL);
	if (!list->_.hash) {
		rc = errno;
		goto err;
	}

	rc = 0;
	goto cleanup;

err:
	__bmc_list_cleanup(list);

cleanup:
	if (ptn_iter)
		bstore_ptn_iter_free(ptn_iter);
out:
	return rc;
}

/*
 * This function modifies ptn content, extracting only the 'WORD' tokens.
 */
static
void __ptn_to_word_sig(bptn_t ptn)
{
	btkn_id_t tkn_id;
	btkn_type_t tkn_type;
	int i, j;
	j = 0;
	for (i = 0; i < ptn->tkn_count; i++) {
		tkn_id = ptn->str->u64str[i];
		tkn_type = tkn_id & 0xFF;
		tkn_id >>= 8;
		if (tkn_type != BTKN_TYPE_WORD)
			continue;
		ptn->str->u64str[j] = ptn->str->u64str[i];
		j++;
	}
	ptn->tkn_count = j;
	ptn->str->blen = j * sizeof(uint64_t);
}

/*
 * Group ptns of the same WORD signature
 */
static
int __bmc_list_compute_bmc_by_word(bstore_t bs, bmc_list_t list)
{
	int rc;
	uint64_t k;
	bptn_t ptn;
	struct bhash_entry *hent;
	struct bmc_s *bmc;
	struct bmc_entry_s *bmc_ent;

	k = 0;

	while ((bmc_ent = TAILQ_FIRST(&list->_.ent_head))) {
		TAILQ_REMOVE(&list->_.ent_head, bmc_ent, link);
		ptn = bptn_dup(bmc_ent->ptn);
		if (!ptn) {
			rc = errno;
			goto out;
		}
		__ptn_to_word_sig(ptn);
		hent = bhash_entry_get(list->_.hash, ptn->str->cstr,
				       ptn->str->blen);
		if (!hent) {
			/* first entry of the group, get new bmc */
			bmc = __bmc_alloc();
			bmc_ent->meta_id = bmc->meta_id = 0;
			bmc->meta_ptn = ptn;
			k++;
			hent = bhash_entry_set(list->_.hash, ptn->str->cstr,
					       ptn->str->blen, (uint64_t)bmc);
			if (!hent) {
				rc = errno;
				goto out;
			}
			TAILQ_INSERT_TAIL(&list->bmc_head, bmc, link);
			list->bmc_n++;
		} else {
			bptn_free(ptn);
			bmc = (void*)hent->value;
			bmc_ent->meta_id = 0;
		}
		TAILQ_INSERT_TAIL(&bmc->ent_head, bmc_ent, link);
	}
	rc = 0;
out:
	return rc;
}

typedef struct __bmc_stack_entry_s {
	bmc_t bmc;
	bmc_t bmcx;
} *__bmc_stack_entry_t;

/*
 * Merge groups of similar WORD signature.
 */
static
int __bmc_list_compute_bmc_span(bstore_t bs, bmc_list_t list)
{
	int rc;
	bptn_id_t meta_id = 256;
	struct __bmc_stack_entry_s *stack = NULL;
	int tos;
	bmc_t bmc, bmcx, bmcy;
	bmc_t *bmc_array;
	int maxlen;
	float dist;
	void *buff = NULL;
	size_t buffsz;

	buffsz = 16*1024*1024;
	buff = malloc(buffsz);
	if (!buff) {
		rc = errno;
		goto cleanup;
	}

	stack = malloc(list->bmc_n * sizeof(stack[0]));
	if (!stack) {
		rc = errno;
		goto cleanup;
	}

	/* spanning tree */
	bmc = TAILQ_FIRST(&list->bmc_head);
	tos = 0;
	bmc->meta_id = meta_id;
	stack[tos].bmc = bmc;
	stack[tos].bmcx = NULL;

span:
	/* assumes non-empty stack */
	assert(tos >= 0);
	bmc = stack[tos].bmc;
	bmcx = stack[tos].bmcx;

	if (!bmcx)
		bmcx = TAILQ_FIRST(&list->bmc_head);
	else
		bmcx = TAILQ_NEXT(bmcx, link);

	while (bmcx) {
		if (bmcx->meta_id)
			goto next;
		maxlen = BMAX(bmc->meta_ptn->str->blen,
			      bmcx->meta_ptn->str->blen) / sizeof(uint64_t);
		dist = bstr_lev_dist_u64(bmc->meta_ptn->str,
					 bmcx->meta_ptn->str, buff, buffsz)
				/ (float)maxlen;
		if (dist < 0)
			goto next;
		/* NOTE: we don't need distance caching here because each bmc
		 *       pair is evaluated only twice at the maximum.
		 */
		if (dist < list->_.params.diff_ratio) {
			/* save current state */
			stack[tos].bmcx = bmcx;
			bmcx->meta_id = bmc->meta_id;
			/* push */
			stack[++tos].bmc = bmcx;
			stack[tos].bmcx = NULL;
			assert(tos < list->bmc_n);
			goto span;
		}
		/* else, do nothing */
	next:
		bmcx = TAILQ_NEXT(bmcx, link);
	}
	tos--; /* pop */
	if (tos >= 0)
		goto span;
	/* end of span */

	/* stack empty, do the next span */
	for (bmc = TAILQ_NEXT(bmc, link); bmc; bmc = TAILQ_NEXT(bmc, link)) {
		if (bmc->meta_id)
			continue;
		meta_id++;
		bmc->meta_id = meta_id;
		tos = 0;
		stack[tos].bmc = bmc;
		stack[tos].bmcx = NULL;
		goto span;
	}

	bmc_array = buff;
	if ((void*)&bmc_array[meta_id] > (buff + buffsz)) {
		/* not enough buff */
		free(buff);
		buff = calloc(1, meta_id * sizeof(bmc_array[0]));
		if (!buff) {
			rc = errno;
			goto cleanup;
		}
	}

	/* now, merge bmcs */
	bmcx = TAILQ_FIRST(&list->bmc_head);
	while (bmcx) {
		bmcy = TAILQ_NEXT(bmcx, link);
		bmc = bmc_array[bmcx->meta_id];
		if (bmc) {
			/* merge */
			TAILQ_CONCAT(&bmc->ent_head, &bmcx->ent_head, link);
			/* remove + free the empty bmc */
			TAILQ_REMOVE(&list->bmc_head, bmcx, link);
			__bmc_free(bmcx);
		} else {
			bmc_array[bmcx->meta_id] = bmcx;
		}
		bmcx = bmcy;
	}
	rc = 0;

cleanup:
	if (buff)
		free(buff);
	if (stack)
		free(stack);
	return rc;
}

static
float __bmc_ent_dist(bmc_entry_t a, bmc_entry_t b, bmc_list_t list)
{
	uint64_t idx;
	uint64_t i, j, n, tmp;
	struct __bmc_ent_dist_cache *c = list->_.dist_cache;
	n = c->max_id - 256;
	i = a->ptn->ptn_id - 256;
	j = b->ptn->ptn_id - 256;
	if (i > j) {
		tmp = i;
		i = j;
		j = tmp;
	}
	idx = (i*n+j) - (i+1)*(i+2)/2;
	if (!c->dist[idx]) {
		tmp = BMAX(a->ptn->str->blen, b->ptn->str->blen)
					/ sizeof(uint64_t);
		c->dist[idx] = bstr_lev_dist_u64(a->ptn->str, b->ptn->str,
						 list->_.buff, list->_.buffsz)
					/ (float)tmp;
	}
	return c->dist[idx];
}

static
float __bmc_avg_dist(bmc_t bmc, bmc_list_t list)
{
	float avg = 0;
	float dist, n = 0;
	bmc_entry_t bmc_ent, bmc_entx;
	BMC_FOREACH(bmc_ent, bmc) {
		bmc_entx = bmc_ent;
		while ((bmc_entx = TAILQ_NEXT(bmc_entx, link))) {
			dist = __bmc_ent_dist(bmc_ent, bmc_entx, list);
			avg += dist;
			n += 1;
		}
	}
	return avg / n;
}

typedef struct __bmc_ent_stack_entry_s {
	union {
		struct {
			bmc_entry_t bmc_ent;
			bmc_entry_t bmc_entx;
		};
		TAILQ_HEAD(, bmc_entry_s) head;
	};
} *__bmc_ent_stack_entry_t;

static
int __bmc_span(bmc_t bmc, bmc_list_t list)
{
	int rc;
	bmc_t bmcx;
	bmc_entry_t bmc_ent, bmc_entx;
	struct __bmc_ent_stack_entry_s *stack;
	float dist;
	int tos;
	int n;
	int x;

	/* clear label */
	n = 0;
	BMC_FOREACH(bmc_ent, bmc) {
		bmc_ent->meta_id = 0;
		n++;
	}
	stack = malloc(n * sizeof(stack[0]));
	if (!stack) {
		rc = errno;
		goto out;
	}

	x = 0;
	bmc_ent = TAILQ_FIRST(&bmc->ent_head);
	bmc_ent->meta_id = bmc->meta_id;
	tos = 0;
	stack[tos].bmc_ent = bmc_ent;
	stack[tos].bmc_entx = bmc_ent;

span:
	bmc_ent = stack[tos].bmc_ent;
	bmc_entx = stack[tos].bmc_entx;
	if (bmc_entx)
		bmc_entx = TAILQ_NEXT(bmc_entx, link);
	else
		bmc_entx = TAILQ_FIRST(&bmc->ent_head);
	while (bmc_entx) {
		if (bmc_entx->meta_id)
			continue; /* already labeled */
		dist = __bmc_ent_dist(bmc_ent, bmc_entx, list);
		if (dist < 0)
			continue;
		if (dist < bmc->_.dist_thr) {
			/* save bmc_entx */
			stack[tos].bmc_entx = bmc_entx;

			/* span to bmc_entx */
			bmc_entx->meta_id = bmc_ent->meta_id;
			stack[++tos].bmc_ent = bmc_entx;
			stack[tos].bmc_entx = NULL;
			assert(tos < n);
			goto span;
		}
		bmc_entx = TAILQ_NEXT(bmc_entx, link);
	}
	tos--; /* pop */
	if (tos >= 0)
		goto span;

	/* stack empty, do the next span if needed */
	BMC_FOREACH(bmc_ent, bmc) {
		if (bmc_ent->meta_id)
			continue;
		x++;
		bmc_ent->meta_id = bmc->meta_id + x; /* temp meta_id */
		tos = 0;
		stack[tos].bmc_ent = bmc_ent;
		stack[tos].bmc_entx = bmc_ent;
		goto span;
	}

	/* spanning done .. regroup */
	for (x = 0; x < n; x++) {
		TAILQ_INIT(&stack[x].head);
	}
	bmc_ent = TAILQ_FIRST(&bmc->ent_head);
	while (bmc_ent) {
		bmc_entx = TAILQ_NEXT(bmc_ent, link);
		if (bmc_ent->meta_id == bmc->meta_id)
			goto skip;
		TAILQ_REMOVE(&bmc->ent_head, bmc_ent, link);
		x = bmc_ent->meta_id - bmc->meta_id;
		TAILQ_INSERT_TAIL(&stack[x].head, bmc_ent, link);
	skip:
		bmc_ent = bmc_entx;
	}
	for (x = 0; x < n; x++) {
		if (TAILQ_EMPTY(&stack[x].head))
			continue;
		bmcx = __bmc_alloc();
		if (!bmcx) {
			rc = errno;
			goto cleanup;
		}
		TAILQ_CONCAT(&bmcx->ent_head, &stack[x].head, link);
		TAILQ_INSERT_TAIL(&list->bmc_head, bmcx, link);
		bmcx->meta_id = 256 + list->bmc_n;
		list->bmc_n++;
		BMC_FOREACH(bmc_ent, bmcx) {
			bmc_ent->meta_id = bmcx->meta_id;
		}
	}

	rc = 0;

cleanup:
	for (x = 0; x < n; x++) {
		/* make sure that the list is empty. Otherwise, put them
		 * together with the bmc for the cleanup afterward. */
		if (TAILQ_EMPTY(&stack[x].head))
			continue;
		TAILQ_CONCAT(&bmc->ent_head, &stack[x].head, link);
	}
	free(stack);
out:
	return rc;
}

/*
 * The refinement process may split a bmc into many bmcs. The extra bmcs will be
 * inserted to the end of the list, which will be refined later if needed (see
 * __bmc_list_compute_bmc_refine()).
 */
static
int __bmc_refine(bmc_t bmc, bmc_list_t list)
{
	int rc;
	float avg_dist;

refine:
	/* reaching here means average distance > looseness */

	/* need to crank up the threshold */
	bmc->_.dist_thr /= list->_.params.refinement_speed;

	/* cluster by spanning tree */
	rc = __bmc_span(bmc, list);
	avg_dist = __bmc_avg_dist(bmc, list);
	if (avg_dist > list->_.params.looseness)
		goto refine; /* keep refining until we have an acceptable
			      * average distances. */
	rc = 0;
	return rc;
}

/*
 * Refine each bmc.
 */
static
int __bmc_list_compute_bmc_refine(bstore_t bs, bmc_list_t list)
{
	int rc;
	float avg_dist;
	bmc_t bmc;

	list->_.dist_cache = __bmc_ent_dist_cache_alloc(list);
	if (!list->_.dist_cache) {
		rc = errno;
		goto cleanup;
	}

	BMC_LIST_FOREACH(bmc, list) {
		avg_dist = __bmc_avg_dist(bmc, list);
		if (avg_dist > list->_.params.looseness) {
			rc = __bmc_refine(bmc, list);
			if (rc)
				goto cleanup;
		}
	}

	rc = 0;
cleanup:
	if (list->_.dist_cache) {
		/* We're done with the cache. No need to keep it around. */
		__bmc_ent_dist_cache_free(list->_.dist_cache);
		list->_.dist_cache = NULL;
	}
	return rc;
}

static
void __dprint_bmc_entry(bmc_entry_t bmc_ent)
{
	printf("bmc_ent: %p\n", bmc_ent);
	printf("\tptn_id: %lu\n", bmc_ent->ptn->ptn_id);
	printf("\tptn_ref: %p\n", bmc_ent->ptn);
}

static
void __dprint_bmc(bmc_t bmc)
{
	int n = 0;
	bmc_entry_t bmc_ent;
	TAILQ_FOREACH(bmc_ent, &bmc->ent_head, link) {
		__dprint_bmc_entry(bmc_ent);
		n++;
	}
	printf("n: %d\n", n);
}

static
int __bmc_compute_name(bmc_t bmc, bmc_list_t list)
{
	bmc_entry_t bmc_ent;
	int rc;
	int i;
	int idx_len;
	uint64_t *a, *b;
	int a_len, b_len;
	bptn_t lcs_ptn;
	bmc_ent = TAILQ_FIRST(&bmc->ent_head);
	lcs_ptn = bptn_dup(bmc_ent->ptn);
	bmc_ent = TAILQ_NEXT(bmc_ent, link);
	idx_len = list->_.lcs_idx_len;
	if (bmc->meta_ptn) {
		bptn_free(bmc->meta_ptn);
		bmc->meta_ptn = NULL;
	}
	while (bmc_ent) {
		idx_len = list->_.lcs_idx_len;
		rc = bstr_lcsX_u64(lcs_ptn->str,
				   bmc_ent->ptn->str,
				   list->_.lcs_idx,
				   &idx_len,
				   list->_.buff,
				   list->_.buffsz);
		if (rc) {
			bmc->meta_ptn = bptn_dup(&ERR_PTN);
			goto out;
		}
		/* update lcs string */
		for (i = 0; i < idx_len; i++) {
			lcs_ptn->str->u64str[i] =
				lcs_ptn->str->u64str[list->_.lcs_idx[i]];
		}
		lcs_ptn->str->blen = idx_len * sizeof(btkn_id_t);

		/* next */
		bmc_ent = TAILQ_NEXT(bmc_ent, link);
	}
	/* now, lcs_ptn is the cumulative lcs from above. This is not the
	 * same as an lcs of N sequences. However, this cumulative lcs seems
	 * suffice to produce a meta pattern. */
	bmc->meta_ptn = bptn_dup(TAILQ_FIRST(&bmc->ent_head)->ptn);
	a = lcs_ptn->str->u64str;
	b = bmc->meta_ptn->str->u64str;
	a_len = lcs_ptn->str->blen / sizeof(*a);
	b_len = bmc->meta_ptn->str->blen / sizeof(*b);
	/* meta-pattern heuristic: take the first pattern, and mark the tokens
	 * not matching those in the cumulative lcs as '*' */
	while (a_len && b_len) {
		if (*a == *b) {
			/* a match ... move both str to the next token */
			a++;
			a_len--;
			b++;
			b_len--;
		} else {
			*b = (BTKN_TYPE_TEXT<<8)|BTKN_TYPE_TEXT;
			b++;
			b_len--;
		}
	}
	assert(a_len == 0); /* because `a` is a subsequence of all ptns */
	/* then, make the rest of b to TEXT */
	while (b_len) {
		*b = (BTKN_TYPE_TEXT<<8)|BTKN_TYPE_TEXT;
		b++;
		b_len--;
	}
	bptn_free(lcs_ptn);
	rc = 0;
out:
	return rc;
}

static
int __bmc_list_compute_bmc_name(bstore_t bs, bmc_list_t list)
{
	int rc;
	bmc_t bmc;
	BMC_LIST_FOREACH(bmc, list) {
		rc = __bmc_compute_name(bmc, list);
		if (rc && rc != ENOMEM)
			goto out;
	}
	rc = 0;
out:
	return rc;
}

bmc_list_t bmc_list_compute(bstore_t bs, bmc_params_t params)
{
	int rc = 0;
	struct bmc_list_s *list = calloc(1, sizeof(*list));

	if (!list)
		goto err;
	bmc_list_init(list);
	list->_.params = *params;

	rc = __bmc_list_pre_compute(bs, list);
	if (rc)
		goto err;
	rc = __bmc_list_compute_bmc_by_word(bs, list);
	if (rc)
		goto err;
	rc = __bmc_list_compute_bmc_span(bs, list);
	if (rc)
		goto err;
	rc = __bmc_list_compute_bmc_refine(bs, list);
	if (rc)
		goto err;
	rc = __bmc_list_compute_bmc_name(bs, list);
	if (rc)
		goto err;
	return (bmc_list_t)list;
err:
	if (list)
		bmc_list_free((bmc_list_t)list);
	return NULL;
}

void bmc_list_free(bmc_list_t bmc_list)
{
	__bmc_list_cleanup(bmc_list);
	free(bmc_list);
}

__attribute__((constructor))
void __bmc_init_once()
{
	ERR_PTN.str->blen = 8*2;
	ERR_PTN.str->u64str[0] = (BTKN_TYPE_FLOAT << 8) | BTKN_TYPE_TYPE;
	ERR_PTN.str->u64str[1] = (BTKN_TYPE_SERVICE << 8) | BTKN_TYPE_TYPE;
}

/* Utilities to aid Cython */

struct bmc_list_iter_s {
	bmc_list_t bmc_list;
	bmc_t bmc;
};

struct bmc_iter_s {
	bmc_t bmc;
	bmc_entry_t bmc_ent;
};

bmc_list_iter_t bmc_list_iter_new(bmc_list_t bmc_list)
{
	bmc_list_iter_t iter = calloc(1, sizeof(*iter));
	if (!iter)
		return NULL;
	iter->bmc_list = bmc_list;
	return iter;
}

bmc_t bmc_list_iter_first(bmc_list_iter_t iter)
{
	iter->bmc = TAILQ_FIRST(&iter->bmc_list->bmc_head);
	return iter->bmc;
}

bmc_t bmc_list_iter_next(bmc_list_iter_t iter)
{
	if (!iter->bmc)
		return NULL;
	iter->bmc = TAILQ_NEXT(iter->bmc, link);
	return iter->bmc;
}

void bmc_list_iter_free(bmc_list_iter_t iter)
{
	free(iter);
}

bmc_iter_t bmc_iter_new(bmc_t bmc)
{
	bmc_iter_t iter = calloc(1, sizeof(*iter));
	if (!iter)
		return NULL;
	iter->bmc = bmc;
	return iter;
}

bptn_t bmc_iter_first(bmc_iter_t iter)
{
	iter->bmc_ent = TAILQ_FIRST(&iter->bmc->ent_head);
	return iter->bmc_ent->ptn;
}

bptn_t bmc_iter_next(bmc_iter_t iter)
{
	if (!iter->bmc_ent)
		return NULL;
	iter->bmc_ent = TAILQ_NEXT(iter->bmc_ent, link);
	if (!iter->bmc_ent)
		return NULL;
	return iter->bmc_ent->ptn;
}

void bmc_iter_free(bmc_iter_t iter)
{
	free(iter);
}
