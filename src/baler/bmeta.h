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

/**
 * \file bmeta.h
 * \author Narate Taerat (narate at ogc dot us)
 * \brief Baler meta cluster algorithm.
 *
 *****************************************************************************
 * \note The prefix for baler meta cluster types and functions in this file is
 *       \c bmc_ as it is much shorter than \c bmeta_cluster_.
 *****************************************************************************
 */
#ifndef __BMETA_H
#define __BMETA_H

#include <sys/queue.h>
#include "bstore.h"

typedef uint32_t bmc_id_t;

typedef struct bmc_params_s {
	float diff_ratio;
	float looseness;
	float refinement_speed;
} *bmc_params_t;

typedef struct bmc_entry_s {
	bmc_id_t meta_id;
	bptn_t ptn;
	TAILQ_ENTRY(bmc_entry_s) link;
} *bmc_entry_t;

/* a cluster is a group of bmc_entry */
typedef struct bmc_s {
	bmc_id_t meta_id; /* ID/label of the cluster */
	bptn_t meta_ptn; /* a bptn describing the meta-pattern */
	TAILQ_HEAD(, bmc_entry_s) ent_head; /* list of bmc_entry in the cluster */
	TAILQ_ENTRY(bmc_s) link;

	/* the following are for internal usage */
	struct {
		float dist_thr;
	} _;
} *bmc_t;

typedef struct bmc_list_s {
	TAILQ_HEAD(, bmc_s) bmc_head;
	uint32_t bmc_n;

	/* the following are for internal usage */
	struct {
		struct bmc_params_s params;
		TAILQ_HEAD(, bmc_entry_s) ent_head;
		uint32_t ent_n;
		struct bhash *hash;
		size_t buffsz;
		void *buff;
		int lcs_idx_len;
		int *lcs_idx;
		void *dist_cache;
	} _;
} *bmc_list_t;

#define BMC_LIST_FOREACH(bmc, bmc_list) \
		TAILQ_FOREACH(bmc, &bmc_list->bmc_head, link)
#define BMC_FOREACH(bmc_entry, bmc) \
		TAILQ_FOREACH(bmc_entry, &bmc->ent_head, link)

/**
 * Initialize \c bmc_list before \c bmc_list_compute().
 */
void bmc_list_init(struct bmc_list_s *bmc_list);

/**
 * \brief Perform meta-clustering algorithm on patterns in the store.
 *
 * This function computes baler meta clustering according to the given \c
 * params. The returned \c bmc_list is the list of baler meta clusters. The
 * caller can iterate through the list using \c BMC_LIST_FOREAC() macro.
 *
 * \note The computation time can be long.
 *
 * \param bs the baler store handle
 *
 * \retval bmc_list for a success clustering
 * \retval NULL if there is an error. In this case \c errno is set to describe
 *              the error.
 */
bmc_list_t bmc_list_compute(bstore_t bs, bmc_params_t params);

/**
 * \brief Free up the resources allocated for the list.
 */
void bmc_list_free(bmc_list_t bmc_list);


/* Iterators for Cython, as it doesn't work well with macros */
/* *** NOTE *** The caller doesn't own the returned bmc_t or bptn_t */
typedef struct bmc_list_iter_s *bmc_list_iter_t;
bmc_list_iter_t bmc_list_iter_new(bmc_list_t bmc_list);
bmc_t bmc_list_iter_first(bmc_list_iter_t iter);
bmc_t bmc_list_iter_next(bmc_list_iter_t iter);
void bmc_list_iter_free(bmc_list_iter_t iter);

typedef struct bmc_iter_s *bmc_iter_t;
bmc_iter_t bmc_iter_new(bmc_t bmc);
bptn_t bmc_iter_first(bmc_iter_t iter);
bptn_t bmc_iter_next(bmc_iter_t iter);
void bmc_iter_free(bmc_iter_t iter);

#endif
