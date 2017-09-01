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
 * \file n2dassoc.h
 * \author Narate Taerat (narate at ogc dot us)
 */
#ifndef __N2DASSOC_H__
#define __N2DASSOC_H__

#include <limits.h>
#include <n2dassoc/assoc.h>

typedef struct n2dassoc_config_s {
	struct assoc_param_s param;

	/* Left-hand-side (LHS) n2da's can be listed in the `lhs_list_file` or
	 * given in `lhs_list`. The same also applied for RHS. */
	char lhs_list_file[PATH_MAX]; /* can be empty string */
	char rhs_list_file[PATH_MAX]; /* can be empty string */
	char tmpdir[PATH_MAX]; /* n2dassoc tmpdir */
	const char **lhs_list; /* can be NULL, the last entry must be NULL */
	const char **rhs_list; /* can be NULL, the last entry must be NULL */
	char rulefile[PATH_MAX];
} *n2dassoc_config_t;

typedef struct n2dassoc_s *n2dassoc_t;

n2dassoc_t n2dassoc_new(n2dassoc_config_t _cfg);
int n2dassoc_start(n2dassoc_t n2dassoc);
int n2dassoc_stat(n2dassoc_t n2dassoc, assoc_stat_t stat);
int n2dassoc_wait(n2dassoc_t n2dassoc);
int n2dassoc_cacnel(n2dassoc_t n2dassoc);
void n2dassoc_free(n2dassoc_t n2dassoc);

#endif
