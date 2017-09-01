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
 * \file assoc.h
 * \author Narate Taerat (narate at ogc dot us)
 */
#ifndef __ASSOC_H__
#define __ASSOC_H__

#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

typedef uint64_t item_id_t;

typedef struct assoc_rule_s {
	double conf;
	double sig;
	int n;
	int lhs_last_idx;
	item_id_t rhs;
	item_id_t lhs[0];
} *assoc_rule_t;
typedef const struct assoc_rule_s *const_assoc_rule_t;

typedef struct assoc_support_ctxt_s {
	int thread_number;
	void *arg;
} *assoc_support_ctxt_t;

typedef struct assoc_param_s {
	int lhs_n; /* number of left-hand-side items */
	int rhs_n; /* number of right-hand-side items */
	int max_depth; /* max depth for breadth-first-search */
	size_t q_sz; /* size of the queue for bfs, default is 1GB */
	const item_id_t *lhs_items; /* antecedents (left-hand-side) */
	const item_id_t *rhs_items; /* targets to mine the rules for (right-hand-side) */
	int threads; /* number of assoc threads */

	/* support() is called to evaluate the support of the item set */
	double (*support)(int n, const item_id_t *ids, assoc_support_ctxt_t arg);

	/* finalize() is called when the mining is finished or cancelled */
	int (*finalize)(assoc_support_ctxt_t arg);

	double conf; /* CONF threshold */
	double sig; /* SIG threshold */
	double diff; /* DIFF threshold */
	void *arg; /* arg to supply to `support()` */
	char tmp_dir[PATH_MAX]; /* path to tmp dir */
	char ar_path[PATH_MAX]; /* path to the assoc-rule result (output) */
} *assoc_param_t;
typedef const struct assoc_param_s *const_assoc_param_t;

typedef enum assoc_state_e {
	ASSOC_STATE_INIT,
	ASSOC_STATE_DONE,
	ASSOC_STATE_BUSY,
	ASSOC_STATE_CANCELLING,
	ASSOC_STATE_FINALIZING,
	ASSOC_STATE_ERROR,
	ASSOC_STATE_CANCELED,
} assoc_state_t;

typedef struct assoc_stat_s {
	enum assoc_state_e state; /* state of the assoc routine */
	int rc; /* describing the error for ASSOC_STATE_ERROR */
	int depth; /* current depth */
	uint64_t rules; /* number of rules found */
	uint64_t candidates; /* number of candidates evaluated */
} *assoc_stat_t;

typedef struct aq_s *aq_t;
typedef struct assoc_s *assoc_t;
typedef struct assoc_rule_file_s *assoc_rule_file_t;

/**
 * Create a new \c assoc handle with corresponding \c param.
 *
 * \param param The association rule mining parameters.
 */
assoc_t assoc_new(const_assoc_param_t param);

/**
 * Free the \c assoc and its resources.
 */
void assoc_free(assoc_t assoc);

/**
 * Start mining routine.
 *
 * This function is non-blocking. The status of the mining routine can be
 * checked via \c assoc_stat(). Alternatively, the caller may call \c
 * assoc_wait() to blocking-wait for the routine to finish.
 *
 * \param assoc the association rule mining handle.
 *
 * \retval 0 if the routine start successfully.
 * \retval errno if there is an error.
 */
int assoc_mine(assoc_t assoc);

/**
 * Blocking-wait for the mining routine to complete.
 *
 * \retval 0 for no errors.
 * \retval errno if there is an error.
 */
int assoc_wait(assoc_t assoc);

/**
 * Cancel the mining operation.
 *
 * \retval 0 if success.
 * \retval errno if error.
 */
int assoc_cancel(assoc_t assoc);

/**
 * Check the mining status.
 *
 * \retval 0 if there is no error.
 * \retval errno if there is an error.
 */
int assoc_stat(assoc_t assoc, assoc_stat_t stat);

/**
 * Print \c stat to \c stream.
 *
 * \note See \c open_memstream() function in \c fmemopen(3) for opening memory
 * as a stream.
 *
 * \retval -1 if there is an error.
 * \retval bytes The number of bytes written to the stream.
 */
int assoc_stat_print(FILE *stream, const assoc_stat_t stat);

/**
 * Open the assoc rule file for reading.
 */
assoc_rule_file_t assoc_rule_file_open(const char *path);

/**
 * Close the assoc rule file.
 */
void assoc_rule_file_close(assoc_rule_file_t ar_file);

/**
 * \note This function is NOT thread-safe.
 */
const_assoc_rule_t assoc_rule_file_read(assoc_rule_file_t ar_file);

/**
 * Dump the content of the \c ar_file to \c stream.
 */
void assoc_rule_file_dump(FILE *stream, assoc_rule_file_t ar_file, int hex);

/**
 * Verify the rules in \c ar_file.
 *
 * \retval 0 if the file is verified with no error.
 * \retval errno if there is an error.
 */
int assoc_rule_file_verify(assoc_rule_file_t ar_file);

/**
 * Print rules to \c stream.
 *
 * \param stream The output stream.
 * \param r The rule to print.
 * \param hex !0 for printing item IDs as hexadecimals. 0 for decimal printing.
 */
int assoc_rule_print(FILE *stream, const_assoc_rule_t r, int hex);

/**
 * Iterate over current rules.
 *
 * \retval 0 If there is no error.
 * \retval non_zero If underlying memory mapping failed, or the \c cb() function
 *                  returns non-zero value. In the latter case, the function
 *                  return code is the one returned from \c cb() function.
 */
int assoc_rule_foreach(assoc_t assoc,
		       int (*cb)(const_assoc_rule_t rule, void *arg),
		       void *arg);
#endif
