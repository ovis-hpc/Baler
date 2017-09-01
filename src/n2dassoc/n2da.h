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
 * \file n2da.h
 * \author Narate Taerat (narate at ogc dot us)
 */
#ifndef __N2DA_H__
#define __N2DA_H__

#include <stdint.h>
#include <fcntl.h>

typedef struct n2da_hdr_s {
	union {
		struct {
			char name[256]; /* null-terminated; max 255 chars */
			uint64_t x_bin_width;
			uint64_t y_bin_width;
			uint64_t total_count;
			uint64_t cell_count;
		};
		char _[4096]; /* reserved 4K header for future expansion */
	};
} *n2da_hdr_t;
typedef const struct n2da_hdr_s *const_n2da_hdr_t;

typedef struct n2da_cell_s {
	uint64_t p[0]; /* convenient, p[0]: x, p[1]: y, p[2]: count */
	uint64_t x;
	uint64_t y;
	uint64_t count;
} *n2da_cell_t;
typedef const struct n2da_cell_s *const_n2da_cell_t;

static inline
int n2da_cell_xy_cmp(const_n2da_cell_t __restrict__ a,
		  const_n2da_cell_t __restrict__ b)
{
	int i;
	int64_t tmp;
	for (i = 0; i < 2; i++) {
		tmp = a->p[i] - b->p[i];
		if (tmp)
			return tmp;
	}
	return 0;
}

/*
 * n2da file format
 */
typedef struct n2da_file_s {
	struct n2da_hdr_s hdr;
	struct n2da_cell_s data[0];
} *n2da_file_t;

typedef struct n2da_s {
	int fd;
	char path[4096];
	n2da_file_t file;
	uint64_t file_len;
	struct n2da_cell_s last_cell;
} *n2da_t;

/**
 * Open a named-2d-array file.
 *
 * This function also call \c n2da_create() if \c O_CREAT is in the \c flags.
 * In this case, \c mode and \c hdr function arguments are required and are
 * supplied to the subsequent \c n2da_create().
 *
 * \param path The path of the file.
 * \param flags The OR combination of \c O_* (e.g. \c O_RDWR, and \c O_CREAT)
 *              open(2) options.
 * \param mode The mode of the file for \c O_CREAT.
 * \param hdr The header for \c O_CREAT.
 *
 * \retval n2da The named-2d-array handle, if the open is a success.
 * \retval NULL If the open is a failure. In this case, \c errno is also set.
 */
n2da_t n2da_open(const char *path, int flags, ...);

/**
 * Open a named-2d-array file in the directory referred to by \c dir_fd.
 */
n2da_t n2da_open_at(int dir_fd, const char *fname, int flags, ...);

/**
 * Create an n2da file with given \c hdr.
 *
 * \param path The file path.
 * \param mode The \c mode of the file (e.g. \c 0644).
 * \param hdr The header for file initialization. This must NOT be \c NULL.
 *
 * \retval 0 if success.
 * \retval errno if error.
 */
int n2da_create(const char *path, mode_t mode, const_n2da_hdr_t hdr);

/**
 * Create an n2da file in the directory referred to by \c dir_fd.
 */
int n2da_create_at(int dir_fd, const char *fname, mode_t mode,
		   const_n2da_hdr_t hdr);

/**
 * Close the n2da handle.
 */
void n2da_close(n2da_t n2da);

/**
 * Set \c n2da header.
 *
 * \retval 0 for success
 * \retval errno for error
 */
int n2da_set_hdr(n2da_t n2da, const struct n2da_hdr_s *__restrict__ hdr);

/**
 * Refresh the memory mapping of the \c n2da.
 *
 * \retval 0 for success
 * \retval errno for error
 */
int n2da_map_refresh(n2da_t n2da);

/**
 * Append the \c cell to \c n2da file.
 *
 * \retval 0 if success.
 * \retval errno if failed.
 */
int n2da_append(n2da_t n2da, const struct n2da_cell_s *__restrict__ cell);

/**
 * Truncate the \c n2da file beyond the last cell.
 *
 * \retval 0 if success.
 * \retval EINVAL if \c n2da is not opened for writing.
 * \retval errno for other errors (arise from \c ftruncate())
 */
int n2da_truncate(n2da_t n2da);

/**
 * Dump n2da contents through STDOUT.
 */
void n2da_dump(n2da_t n2da);

/**
 * Reset the data array in the \c n2da file.
 */
void n2da_reset(n2da_t n2da);

/**
 * Perform cell-wise intersection of \c n0 and \c n1 into \c result.
 */
int n2da_intersect(n2da_t n0, n2da_t n1, n2da_t result);

#endif
