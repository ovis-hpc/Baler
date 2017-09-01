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

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>

#include "n2da.h"

const char *short_opts = "dgv";
const struct option long_opts[] = {
	{"dump",      0,  0,  'd'},
	{"generate",  0,  0,  'g'},
	{"verify",    0,  0,  'v'},
	{0,           0,  0,  0}
};

int mode = 0;
const char *path = NULL;
const int N = 64;

struct n2da_hdr_s hdr = {
	.name = "Test",
	.x_bin_width = 60,
	.y_bin_width = 1,
};

void handle_args(int argc, char **argv)
{
	int c;
	c = getopt_long(argc, argv, short_opts, long_opts, NULL);
	switch (c) {
	case 'd':
	case 'g':
	case 'v':
		mode = c;
		break;
	case -1:
		break;
	default:
		assert(0);
	}
	if (optind >= argc) {
		printf("ERROR: A file path is needed\n");
		exit(-1);
	}
	path = argv[optind];
}

struct n2da_cell_s get_cell(int i)
{
	struct n2da_cell_s c;
	c.x = (i + 1) * 60;
	c.y = i + 1;
	c.count = i+10;
	return c;
}

void generate(const char *path)
{
	n2da_t n2da = n2da_open(path, O_RDWR|O_CREAT|O_TRUNC, 0600, &hdr);
	struct n2da_cell_s c;
	int i, rc;
	if (!n2da) {
		printf("ERROR: n2da_open() failed, errno: %d\n", errno);
		exit(-1);
	}
	for (i = 0; i < N; i++) {
		c = get_cell(i);
		rc = n2da_append(n2da, &c);
		assert(rc == 0);
	}
	n2da_close(n2da);
}

void verify(const char *path)
{
	n2da_t n2da = n2da_open(path, O_RDONLY);
	struct n2da_cell_s c;
	int i, rc;
	uint64_t sum;
	assert(n2da);
	rc = memcmp(&n2da->file->hdr, &hdr,
		    offsetof(struct n2da_hdr_s, total_count));
	if (rc) {
		printf("Verify ERROR: header mismatch\n");
		exit(-1);
	}
	sum = 0;
	for (i = 0; i < N; i++) {
		c = get_cell(i);
		rc = memcmp(&n2da->file->data[i], &c, sizeof(c));
		if (rc) {
			printf("Verify ERROR: data mismatch\n");
			exit(-1);
		}
		sum += c.count;
	}
	if (sum != n2da->file->hdr.total_count) {
		printf("Verify ERROR: total count mismatch\n");
		exit(-1);
	}
	printf("Verified!!!\n");
	n2da_close(n2da);
}

void dump(const char *path)
{
	n2da_t n2da = n2da_open(path, O_RDONLY);
	n2da_dump(n2da);
	n2da_close(n2da);
}

int main(int argc, char **argv)
{
	handle_args(argc, argv);
	printf("path: %s\n", path);
	switch (mode) {
	case 'g':
		generate(path);
		break;
	case 'v':
		verify(path);
		break;
	case 'd':
		dump(path);
		break;
	}
	return 0;
}
