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
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <strings.h>
#include <assert.h>

#include "n2da.h"

static inline
size_t __n2da_logical_len(n2da_t n2da)
{
	return sizeof(struct n2da_hdr_s)
	       + n2da->file->hdr.cell_count * sizeof(struct n2da_cell_s);
}

int n2da_create_at(int dir_fd, const char *fname, mode_t mode,
		   const_n2da_hdr_t hdr)
{
	int fd;
	ssize_t sz;
	fd = openat(dir_fd, fname, O_CREAT|O_WRONLY|O_TRUNC, mode);
	if (fd < 0)
		return errno;
	sz = write(fd, hdr, sizeof(*hdr));
	if (sz != sizeof(*hdr)) {
		close(fd);
		return errno;
	}
	close(fd);
	return 0;
}

int n2da_create(const char *path, mode_t mode, const_n2da_hdr_t hdr)
{
	int fd;
	ssize_t sz;
	fd = creat(path, mode);
	if (fd < 0)
		return errno;
	sz = write(fd, hdr, sizeof(*hdr));
	if (sz != sizeof(*hdr)) {
		close(fd);
		return errno;
	}
	close(fd);
	return 0;
}

n2da_t n2da_open_at(int dir_fd, const char *fname, int flags, ...)
{
	va_list ap;
	int rc, prot;
	off_t off;
	mode_t mode = 0;
	const_n2da_hdr_t hdr = NULL;
	n2da_t n2da = calloc(1, sizeof(*n2da));
	if (!n2da)
		goto err1;
	prot = PROT_READ;
	if ((flags & O_RDWR) || (flags & O_WRONLY)) {
		flags |= O_APPEND;
		prot |= PROT_WRITE;
	}
again:
	n2da->fd = openat(dir_fd, fname, flags & ~O_CREAT);
	if (n2da->fd < 0) {
		if (!(flags & O_CREAT) || errno != ENOENT)
			goto err2;
		/* O_CREAT and ENOENT */
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		hdr = va_arg(ap, const_n2da_hdr_t);
		va_end(ap);
		rc = n2da_create_at(dir_fd, fname, mode, hdr);
		if (rc)
			goto err2;
		flags &= ~(O_CREAT|O_TRUNC); /* create once is enough */
		goto again;
	}
	off = lseek(n2da->fd, 0, SEEK_END);
	if (off < sizeof(struct n2da_hdr_s)) {
		errno = EINVAL;
		goto err3;
	}
	n2da->file_len = off;
	n2da->file = mmap(NULL, n2da->file_len, prot, MAP_SHARED, n2da->fd, 0);
	if (n2da->file == MAP_FAILED)
		goto err3;
	if (flags & O_RDONLY) {
		close(n2da->fd);
		n2da->fd = -1;
	}
	return n2da;

err3:
	close(n2da->fd);
err2:
	free(n2da);
err1:
	return NULL;
}

n2da_t n2da_open(const char *path, int flags, ...)
{
	va_list ap;
	int rc, prot;
	off_t off;
	mode_t mode = 0;
	const_n2da_hdr_t hdr = NULL;
	n2da_t n2da = calloc(1, sizeof(*n2da));
	if (!n2da)
		goto err1;
	rc = snprintf(n2da->path, sizeof(n2da->path), "%s", path);
	if (rc >= 4096)
		goto err2;
	prot = PROT_READ;
	if ((flags & O_RDWR) || (flags & O_WRONLY)) {
		flags |= O_APPEND;
		prot |= PROT_WRITE;
	}
again:
	n2da->fd = open(path, flags & ~O_CREAT);
	if (n2da->fd < 0) {
		if (!(flags & O_CREAT) || errno != ENOENT)
			goto err2;
		/* O_CREAT and ENOENT */
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		hdr = va_arg(ap, const_n2da_hdr_t);
		va_end(ap);
		rc = n2da_create(path, mode, hdr);
		if (rc)
			goto err2;
		flags &= ~(O_CREAT|O_TRUNC); /* create once is enough */
		goto again;
	}
	off = lseek(n2da->fd, 0, SEEK_END);
	if (off < sizeof(struct n2da_hdr_s)) {
		errno = EINVAL;
		goto err3;
	}
	n2da->file_len = off;
	n2da->file = mmap(NULL, n2da->file_len, prot, MAP_SHARED, n2da->fd, 0);
	if (n2da->file == MAP_FAILED)
		goto err3;
	if (flags & O_RDONLY) {
		close(n2da->fd);
		n2da->fd = -1;
	}
	return n2da;

err3:
	close(n2da->fd);
err2:
	free(n2da);
err1:
	return NULL;
}

void n2da_close(n2da_t n2da)
{
	if (n2da->file)
		munmap(n2da->file, n2da->file_len);
	if (n2da->fd >= 0)
		close(n2da->fd);
	free(n2da);
}

int n2da_set_hdr(n2da_t n2da, const struct n2da_hdr_s *__restrict__ hdr)
{
	n2da->file->hdr = *hdr;
	return 0;
}

int n2da_map_refresh(n2da_t n2da)
{
	off_t sz;
	void *ptr;
	if (!n2da->file)
		return ENOENT;
	if (n2da->fd < 0) {
		/* use stat to determine size for O_RDONLY */
		struct stat st;
		int rc;
		rc = stat(n2da->path, &st);
		if (rc == -1)
			return errno;
		sz = st.st_size;
	} else {
		sz = lseek(n2da->fd, 0, SEEK_END);
	}
	if (sz < n2da->file_len) {
		/* file shrink? */
		assert(0 == "n2da file supposed not to shrink ...");
		return EINVAL;
	}
	if (sz == n2da->file_len)
		return 0; /* no need to remap */
	ptr = mremap(n2da->file, n2da->file_len, sz, MREMAP_MAYMOVE);
	if (ptr == MAP_FAILED)
		return errno;
	n2da->file = ptr;
	n2da->file_len = sz;
	return 0;
}

static
int __n2da_extend(n2da_t n2da, size_t ext_sz)
{
	int rc;
	off_t len;
	void *ptr;
	len = lseek(n2da->fd, 0, SEEK_END);
	if (len == -1) {
		rc = errno;
		goto out;
	}
	len += ext_sz;
	len = ((len-1) | 0xFFF)+1;
	rc = ftruncate(n2da->fd, len);
	if (rc) {
		rc = errno;
		goto out;
	}
	ptr = mremap(n2da->file, n2da->file_len, len, MREMAP_MAYMOVE);
	if (ptr == MAP_FAILED) {
		rc = errno;
		goto out;
	}
	n2da->file = ptr;
	n2da->file_len = len;
out:
	return rc;
}

int n2da_append(n2da_t n2da, const struct n2da_cell_s *__restrict__ cell)
{
	int c;
	int rc;
	c = n2da_cell_xy_cmp(&n2da->last_cell, cell);
	if (c >= 0)
		return EINVAL;
	if (__n2da_logical_len(n2da) + sizeof(struct n2da_cell_s) >
				n2da->file_len) {
		/* need extension */
		rc = __n2da_extend(n2da, 0x10000);
		if (rc)
			return rc;
	}
	n2da->file->data[n2da->file->hdr.cell_count++] = *cell;
	n2da->last_cell = *cell;
	n2da->file->hdr.total_count += cell->count;
	return 0;
}

int n2da_truncate(n2da_t n2da)
{
	int rc = 0;
	off_t off = 0;
	if (n2da->fd == -1)
		return EINVAL;
	off = sizeof(n2da->file->hdr)
		+ n2da->file->hdr.cell_count * sizeof(struct n2da_cell_s);
	rc = ftruncate(n2da->fd, off);
	if (rc)
		rc = errno;
	return rc;
}

void n2da_dump(n2da_t n2da)
{
	int i;
	printf("name; %s\n", n2da->file->hdr.name);
	printf("x_bin_width: %lu\n", n2da->file->hdr.x_bin_width);
	printf("y_bin_width: %lu\n", n2da->file->hdr.y_bin_width);
	printf("total_count: %lu\n", n2da->file->hdr.total_count);
	for (i = 0; i < n2da->file->hdr.cell_count; i++) {
		printf("(%lu, %lu, %lu)\n", n2da->file->data[i].x,
					    n2da->file->data[i].y,
					    n2da->file->data[i].count);
	}
}

void n2da_reset(n2da_t n2da)
{
	n2da->file->hdr.total_count = 0;
	n2da->file->hdr.cell_count = 0;
	bzero(&n2da->last_cell, sizeof(n2da->last_cell));
}

int n2da_intersect(n2da_t n0, n2da_t n1, n2da_t result)
{
	int rc;
	int64_t i, j;
	n2da_cell_t c0, c1, lim0, lim1;
	struct n2da_cell_s c;
	n2da_reset(result);
	i = 0;
	j = 0;
	c0 = &n0->file->data[0];
	c1 = &n1->file->data[0];
	lim0 = &n0->file->data[n0->file->hdr.cell_count];
	lim1 = &n1->file->data[n1->file->hdr.cell_count];
	while (c0 < lim0 && c1 < lim1) {
		rc = n2da_cell_xy_cmp(c0, c1);
		if (rc < 0) {
			c0++;
		} else if (rc > 0) {
			c1++;
		} else {
			c.x = c0->x;
			c.y = c0->y;
			c.count = (c0->count < c1->count)?(c0->count):(c1->count);
			rc = n2da_append(result, &c);
			if (rc)
				return rc;
			c0++;
			c1++;
		}
	}
	return 0;
}
