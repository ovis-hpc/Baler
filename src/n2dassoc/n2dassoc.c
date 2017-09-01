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
 * \file n2dassoc.c
 * \author Narate Taerat (narate at ogc dot us)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "assoc.h"
#include "n2da.h"
#include "n2dassoc.h"

typedef struct __stack_s *__stack_t;

/* thread context */
struct __thr_ctxt_s {
	__stack_t n2da_st;
	struct n2da_hdr_s hdr;
	char buff[4096];
};

typedef struct n2dassoc_s {
	assoc_t assoc;
	struct n2dassoc_config_s cfg;
	__stack_t inp_st;
	__stack_t tgt_st;
	struct __thr_ctxt_s *thr_ctxt;
	DIR *tmpdir;
	FILE *output;
} *n2dassoc_t;

/***************/
/*** Utility ***/
/***************/

struct opt_table_s {
	const char *opt;
	int (*fn)(void *var, const char *value);
	void *var;
};

int __opt_tbl_cmp(const void *_a, const void *_b)
{
	const struct opt_table_s *a = _a;
	const struct opt_table_s *b = _b;
	return strcmp(a->opt, b->opt);
}

typedef struct __stack_s {
	int len;
	int alloc_len;
	int element_sz;
	void *data;
} *__stack_t;

static
__stack_t __stack_new(int alloc_len, int element_sz)
{
	__stack_t s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;
	s->len = 0;
	s->alloc_len = alloc_len;
	s->element_sz = element_sz;
	s->data = calloc(alloc_len, element_sz);
	if (!s->data) {
		free(s);
		return NULL;
	}
	return s;
}

static
int __stack_push(__stack_t s, const void *e_ptr)
{
	void *tmp;
	if (s->len < s->alloc_len)
		goto append;
	/* need expansion */
	tmp = realloc(s->data, (s->alloc_len + 4096) * s->element_sz);
	if (!tmp)
		return errno;
	s->alloc_len += 4096;
	bzero(s->data + s->element_sz * s->len,
	      s->element_sz * (s->alloc_len - s->len));
append:
	memcpy(s->data + s->len*s->element_sz, e_ptr, s->element_sz);
	s->len += 1;
	return 0;
}

static
int __stack_alloc(__stack_t s, void *out)
{
	/* allocate the TOS and increase the stack size */
	void *tmp;
	if (s->len < s->alloc_len)
		goto alloc;
	/* need expansion */
	tmp = realloc(s->data, (s->alloc_len + 4096) * s->element_sz);
	if (!tmp)
		return errno;
	s->alloc_len += 4096;
	bzero(s->data + s->element_sz * s->len,
	      s->element_sz * (s->alloc_len - s->len));
alloc:
	memcpy(out, s->data + s->len*s->element_sz, s->element_sz);
	s->len += 1;
	return 0;
}

static
int __stack_update_tos(__stack_t s, void *e_ptr)
{
	if (!s->len)
		return ENOENT;
	memcpy(s->data + (s->len - 1)*s->element_sz, e_ptr, s->element_sz);
	return 0;
}

static
int __stack_pop(__stack_t s, void *out)
{
	if (!s->len)
		return ENOENT;
	s->len--;
	memcpy(out, s->data + s->len * s->element_sz, s->element_sz);
	return 0;
}

static
void __stack_free(__stack_t s)
{
	free(s->data);
	free(s);
}

void __strip(char *str)
{
	int len;
	for (len = strlen(str) - 1; len && iscntrl(str[len]); len--) {
		/* do nothing */
	}
	str[len+1] = 0;
}

static
int __load_n2da_from_file(__stack_t s, const char *lf)
{
	int rc = 0;
	char line[PATH_MAX];
	n2da_t n2da;
	FILE *f = fopen(lf, "r");
	if (!f) {
		rc = errno;
		goto err1;
	}
	while (fgets(line, sizeof(line), f)) {
		__strip(line);
		n2da = n2da_open(line, O_RDONLY);
		if (!n2da) {
			rc = errno;
			goto err2;
		}
		rc = __stack_push(s, &n2da);
		if (rc) {
			n2da_close(n2da);
			goto err2;
		}
	}
	fclose(f);
	return 0;

err2:
	while (__stack_pop(s, &n2da) == 0) {
		n2da_close(n2da);
	}
err1:
	return rc;
}

static
int __load_n2da_from_array(__stack_t s, const char **paths)
{
	int i, rc;
	n2da_t n2da;
	for (i = 0; paths[i]; i++) {
		n2da = n2da_open(paths[i], O_RDONLY);
		if (!n2da) {
			rc = errno;
			goto err1;
		}
		rc = __stack_push(s, &n2da);
		if (rc) {
			n2da_close(n2da);
			goto err1;
		}
	}
	return 0;

err1:
	while (i>0) {
		__stack_pop(s, &n2da);
		n2da_close(n2da);
		i--;
	}
	return rc;
}

static
int __n2dassoc_load_items(n2dassoc_t n2dassoc)
{
	int rc = 0;
	__stack_t lhs_st, rhs_st;
	n2da_t n2da;

	/* Prep LHS & RHS items */

	lhs_st = __stack_new(4096, sizeof(n2da_t));
	if (!lhs_st) {
		rc = errno;
		goto err1;
	}
	if (*n2dassoc->cfg.lhs_list_file) {
		rc = __load_n2da_from_file(lhs_st, n2dassoc->cfg.lhs_list_file);
		if (rc)
			goto err2;
	}
	if (n2dassoc->cfg.lhs_list) {
		rc = __load_n2da_from_array(lhs_st, n2dassoc->cfg.lhs_list);
		if (rc)
			goto err3;
	}

	rhs_st = __stack_new(4096, sizeof(n2da_t));
	if (!rhs_st) {
		rc = errno;
		goto err3;
	}
	if (*n2dassoc->cfg.rhs_list_file) {
		rc = __load_n2da_from_file(rhs_st, n2dassoc->cfg.rhs_list_file);
		if (rc)
			goto err4;
	}
	if (n2dassoc->cfg.rhs_list) {
		rc = __load_n2da_from_array(rhs_st, n2dassoc->cfg.rhs_list);
		if (rc)
			goto err5;
	}

	/* The stack->data is an array of n2da_t (pointers to struct n2da_s) */
	n2dassoc->cfg.param.lhs_n = lhs_st->len;
	n2dassoc->cfg.param.lhs_items = lhs_st->data;
	n2dassoc->cfg.param.rhs_n = rhs_st->len;
	n2dassoc->cfg.param.rhs_items = rhs_st->data;
	/* detach data from the stack */
	free(lhs_st);
	free(rhs_st);
	return 0;

err5:
	while (__stack_pop(rhs_st, &n2da)) {
		n2da_close(n2da);
	}
err4:
	__stack_free(rhs_st);
err3:
	while (__stack_pop(lhs_st, &n2da)) {
		n2da_close(n2da);
	}
err2:
	__stack_free(lhs_st);
err1:
	return rc;
}

static
void __n2dassoc_unload_items(n2dassoc_t n2dassoc)
{
	n2dassoc_config_t cfg = &n2dassoc->cfg;
	assoc_param_t param = &cfg->param;
	int i;
	for (i = 0; i < param->rhs_n; i++) {
		n2da_close((void*)param->rhs_items[i]);
	}
	for (i = 0; i < param->lhs_n; i++) {
		n2da_close((void*)param->lhs_items[i]);
	}
}

static
double __n2dassoc_support(int n, const item_id_t *ids, assoc_support_ctxt_t arg)
{
	n2da_t *a = (void*)ids;
	n2dassoc_t n2dassoc = arg->arg;
	struct __thr_ctxt_s *ctxt = &n2dassoc->thr_ctxt[arg->thread_number];
	n2da_t *cache = ctxt->n2da_st->data;
	int n_cache = ctxt->n2da_st->len;
	n2da_t x;
	int i;
	int rc;
	int dfd;

	/* cache[0] points to the real LHS, not in tmpdir */
	i = 0;
	if (cache[0] != a[0])
		goto skip_cache;
	for (i = 1; i < n_cache; i++) {
		if (*(n2da_t*)cache[i]->file->hdr.name == a[i])
			continue;
		break;
	}
skip_cache:
	/* can use the cache up to i-th entry (0..i-1) */
	if (i == 0) {
		/* Can't use the cache. re-initialize */
		cache[0] = a[0];
		i++;
	}
	ctxt->n2da_st->len = i;
	for (; i < n; i++) {
		rc = __stack_alloc(ctxt->n2da_st, &x);
		if (!x) {
			dfd = dirfd(n2dassoc->tmpdir);
			snprintf(ctxt->buff, sizeof(ctxt->buff),
				 "thr-%d/%d.n2da", arg->thread_number, i);
			bzero(&ctxt->hdr, sizeof(ctxt->hdr));
			x = n2da_open_at(dfd, ctxt->buff, O_RDWR|O_CREAT,
					 0644, &ctxt->hdr);
			if (!x) {
				goto err;
			}
			/* this is cache[i] */
			__stack_update_tos(ctxt->n2da_st, &x);
		}
		*(n2da_t*)x->file->hdr.name = a[i];
		rc = n2da_intersect(cache[i-1], a[i], x);
		if (rc)
			goto err;
	}
	return cache[n-1]->file->hdr.total_count;

err:
	return -1;
}

int __rule_foreach_cb(const_assoc_rule_t r, void *arg)
{
	n2da_t n2da;
	int i, rc = 0;
	n2dassoc_t n2dassoc = arg;
	n2da = (void*)r->lhs[0];
	rc = fprintf(n2dassoc->output, "{%s", n2da->file->hdr.name);
	if (rc < 0) {
		/* ENOSR: No STREAM resources */
		rc = ENOSR;
		goto out;
	}
	for (i = 1; i < r->n; i++) {
		n2da = (void*)r->lhs[i];
		rc = fprintf(n2dassoc->output, ",%s", n2da->file->hdr.name);
		if (rc < 0) {
			rc = ENOSR;
			goto out;
		}
	}
	n2da = (void*)r->rhs;
	rc = fprintf(n2dassoc->output, "}=>{%s}\n", n2da->file->hdr.name);
	if (rc < 0) {
		rc = ENOSR;
		goto out;
	}
	rc = 0;
out:
	return rc;
}

static
int __n2dassoc_finalize(struct assoc_support_ctxt_s *ctxt)
{
	n2dassoc_t n2dassoc = ctxt->arg;
	int rc;
	n2dassoc->output = fopen(n2dassoc->cfg.rulefile, "w");
	if (!n2dassoc->output) {
		rc = errno;
		goto out;
	}
	rc = assoc_rule_foreach(n2dassoc->assoc, __rule_foreach_cb, n2dassoc);
out:
	return rc;
}

static
int __n2dassoc_prep_tmpdir(n2dassoc_t n2dassoc)
{
	int i, dfd, rc;
	struct stat st;
	char buff[128];
	n2dassoc->tmpdir = opendir(n2dassoc->cfg.tmpdir);
	if (!n2dassoc->tmpdir) {
		rc = errno;
		goto err1;
	}
	dfd = dirfd(n2dassoc->tmpdir);
	for (i = 0; i < n2dassoc->cfg.param.threads; i++) {
		snprintf(buff, sizeof(buff), "thr-%d", i);
		rc = mkdirat(dfd, buff, 0755);
		if (rc) {
			if (errno != EEXIST) {
				rc = errno;
				goto err2;
			}
			/* name exist, check if it is a dir */
			rc = fstatat(dfd, buff, &st, 0);
			if (rc) {
				rc = errno;
				goto err2;
			}
			if (!S_ISDIR(st.st_mode)) {
				rc = EINVAL;
				goto err2;
			}
			/* exists && isdir ==> good */
		}
	}
	return 0;
err2:
	closedir(n2dassoc->tmpdir);
	n2dassoc->tmpdir = NULL;
err1:
	return rc;
}

n2dassoc_t n2dassoc_new(n2dassoc_config_t _cfg)
{
	int i;
	int rc;
	struct __thr_ctxt_s *ctxt;
	assoc_param_t param;
	n2dassoc_config_t cfg;
	n2dassoc_t n2dassoc = calloc(1, sizeof(*n2dassoc));
	if (!n2dassoc)
		goto err1;
	n2dassoc->cfg = *_cfg;
	/* set assoc param appropriately */
	cfg = &n2dassoc->cfg;
	param = &cfg->param;
	snprintf(param->tmp_dir, PATH_MAX, "%s/assoc", cfg->tmpdir);
	snprintf(param->ar_path, PATH_MAX, "%s/ar_file", cfg->tmpdir);
	param->support = __n2dassoc_support;
	param->finalize = __n2dassoc_finalize;
	param->arg = n2dassoc;
	rc = __n2dassoc_prep_tmpdir(n2dassoc);
	if (rc)
		goto err2; /* errno has been set */
	if (__n2dassoc_load_items(n2dassoc))
		goto err3; /* errno has been set */
	n2dassoc->thr_ctxt = calloc(cfg->param.threads,
				    sizeof(struct __thr_ctxt_s));
	if (!n2dassoc->thr_ctxt)
		goto err4;
	for (i = 0; i < cfg->param.threads; i++) {
		ctxt = &n2dassoc->thr_ctxt[i];
		ctxt->n2da_st = __stack_new(512, sizeof(n2da_t));
		if (!ctxt->n2da_st)
			goto err5;
	}
	n2dassoc->assoc = assoc_new(&n2dassoc->cfg.param);
	if (!n2dassoc->assoc)
		goto err5;

	return n2dassoc;

err5:
	for (i = 0; i < cfg->param.threads; i++) {
		if (n2dassoc->thr_ctxt[i].n2da_st)
			__stack_free(n2dassoc->thr_ctxt[i].n2da_st);
	}
	free(n2dassoc->thr_ctxt);
err4:
	__n2dassoc_unload_items(n2dassoc);
err3:
err2:
	free(n2dassoc);
err1:
	return NULL;
}

int n2dassoc_start(n2dassoc_t n2dassoc)
{
	return assoc_mine(n2dassoc->assoc);
}

int n2dassoc_stat(n2dassoc_t n2dassoc, assoc_stat_t stat)
{
	int rc;
	rc = assoc_stat(n2dassoc->assoc, stat);
	return rc;
}

int n2dassoc_cacnel(n2dassoc_t n2dassoc)
{
	return assoc_cancel(n2dassoc->assoc);
}

int n2dassoc_wait(n2dassoc_t n2dassoc)
{
	return assoc_wait(n2dassoc->assoc);
}

void n2dassoc_free(n2dassoc_t n2dassoc)
{
	int i;
	if (n2dassoc->assoc) {
		assoc_free(n2dassoc->assoc);
	}
	if (n2dassoc->cfg.param.lhs_items) {
		for (i = 0; i < n2dassoc->cfg.param.lhs_n; i++) {
			n2da_close((void*)n2dassoc->cfg.param.lhs_items[i]);
		}
	}
	if (n2dassoc->cfg.param.rhs_items) {
		for (i = 0; i < n2dassoc->cfg.param.rhs_n; i++) {
			n2da_close((void*)n2dassoc->cfg.param.rhs_items[i]);
		}
	}
	for (i = 0; i < n2dassoc->cfg.param.threads; i++) {
		struct __thr_ctxt_s *ctxt = &n2dassoc->thr_ctxt[i];
		if (ctxt->n2da_st) {
			n2da_t *cache = (void*)ctxt->n2da_st->data;
			int j;
			for (j = 1; j < ctxt->n2da_st->len; j++) {
				n2da_close(cache[j]);
			}
			__stack_free(ctxt->n2da_st);
		}
	}
}

int __handle_cfg_DOUBLE(void *var, const char *v)
{
	*(double*)var = atof(v);
	return 0;
}

int __handle_cfg_INT(void *var, const char *v)
{
	*(int*)var = atoi(v);
	return 0;
}

int __handle_cfg_SZ(void *var, const char *v)
{
	*(size_t*)var = atol(v);
	return 0;
}

int __handle_cfg_STR(void *var, const char *v)
{
	*(const char**)var = v;
	return 0;
}

int __handle_cfg_PATH(void *var, const char *v)
{
	int len = strlen(v);
	if (len > 4095)
		return ENOMEM;
	strcpy(var, v);
	return 0;
}

int __handle_cfg_TARGET(void *var, const char *v)
{
	int rc;
	__stack_t st = var;
	char *x = strdup(v);
	if (!x)
		return ENOMEM;
	rc = __stack_push(st, x);
	if (rc) {
		free(x);
	}
	return rc;
}

int n2dassoc_config_load(const char *path, n2dassoc_config_t cfg, int *line_no)
{
	int i, rc;
	regex_t reg;
	regmatch_t m[3];
	char line[4096];
	char *s, *opt, *value;
	char **rhs_list;
	FILE *f;
	__stack_t rhs_stack;

	rhs_stack = __stack_new(65536, sizeof(const char *));
	if (!rhs_stack) {
		rc = ENOMEM;
		goto err0;
	}
	rc = regcomp(&reg, "[[:space:]]*([[:alnum:]_]+)[[:space:]]*="
			   "[[:space:]]*([^[:cntrl:]]*)[[:cntrl:]]*",
			   REG_EXTENDED);
	if (rc) {
		goto err1;
	}
	f = fopen(path, "r");
	if (!f) {
		rc = errno;
		goto err2;
	}

	struct opt_table_s opt_tbl[] = {
		{"confidence",    __handle_cfg_DOUBLE,  &cfg->param.conf},
		{"difference",    __handle_cfg_DOUBLE,  &cfg->param.diff},
		{"lhsfile",       __handle_cfg_PATH,  cfg->lhs_list_file},
		{"maxdepth",      __handle_cfg_INT,     &cfg->param.max_depth},
		{"qsize",         __handle_cfg_SZ,      &cfg->param.q_sz},
		{"rulefile",      __handle_cfg_PATH,  cfg->rulefile},
		{"significance",  __handle_cfg_DOUBLE,  &cfg->param.sig},
		{"target",        __handle_cfg_TARGET,  rhs_stack},
		{"targetfile",    __handle_cfg_PATH,  cfg->rhs_list_file},
		{"threads",       __handle_cfg_INT,     &cfg->param.threads},
		{"tmpdir",        __handle_cfg_PATH,  cfg->tmpdir},
	};
	int opt_n = sizeof(opt_tbl)/sizeof(opt_tbl[0]);
	struct opt_table_s *opt_ent;
	struct opt_table_s key;

	while (fgets(line, sizeof(line), f)) {
		if (line_no)
			(*line_no)++;

		s = strchr(line, '#');
		if (s)
			*s = 0;
		s = line;
		while (isspace(*s)) {
			s++;
		}
		if (*s == 0) {
			continue;
		}
		rc = regexec(&reg, s, 3, m, 0);
		if (rc == REG_NOMATCH) {
			rc = EINVAL;
			goto err3;
		}
		opt = &s[m[1].rm_so];
		s[m[1].rm_eo] = 0;
		value = &s[m[2].rm_so];
		s[m[2].rm_eo] = 0;
		key.opt = opt;
		opt_ent = bsearch(&key, opt_tbl, opt_n, sizeof(opt_tbl[0]),
				  __opt_tbl_cmp);
		if (!opt_ent) {
			rc = ENOENT;
			goto err3;
		}
		rc = opt_ent->fn(opt_ent->var, value);
		if (rc)
			goto err3;
	}
	cfg->rhs_list = rhs_stack->data;
	free(rhs_stack); /* detach */
	return 0;

err3:
	rhs_list = rhs_stack->data;
	for (i = 0; i < rhs_stack->len; i++) {
		free(rhs_list[i]);
	}
err2:
	regfree(&reg);
err1:
	__stack_free(rhs_stack);
err0:
	return rc;
}

#ifndef LIBN2DASSOC

#include <getopt.h>

/********************/
/* GLOBAL VARIABLES */
/********************/
struct n2dassoc_config_s CFG = {
	.param = {
		/* default values */
		.conf = 0.75,
		.sig = 0.1,
		.diff = 0.1,
		.threads = 4,
		.q_sz = 1024*1024*1024,
		.max_depth = 32,
	},
};

int n_targets = 0;
const char *targets[65536];


/***********/
/* OPTIONS */
/***********/
const char *short_opts = "c:h?";
const struct option long_opts[] = {
	{"config",        1,  0,  'c'},
	{"help",          0,  0,  'h'},
	{0,               0,  0,  0},
};

const char *usage_str = "\n\
usage: n2dassoc -c CONFIG [OPTIONS]\n\
\n\
OPTIONS:\n\
-c,--config FILE	Configuration file.\n\
-h,--help		Help message.\n\
\n\
CONFIG FILE FORMAT:\n\
Each line contains `NAME = VALUE` option, with `#` for comments. Empty lines\n\
are also acceptable.\n\
\n\
CONFIGURATION OPTIONS:\n\
tmpdir = DIR		Temp Directory.\n\
confidence = NUM	Confidence threshold (0.0-1.0).\n\
significance = NUM	Significance threshold (0.0-1.0).\n\
difference = NUM	Difference threshold (0.0-1.0).\n\
target = N2DA_FILE	The n2da target file. This option can be supplied\n\
			multiple times to mine multiple targets.\n\
rulefile = FILE		The output rule file.\n\
targetfile = FILE	The file containing list of target n2da's.\n\
lhsfile = FILE		The file containing list of left-hand-side n2da's.\n\
threads = NUM		The number of miner threads.\n\
maxdepth = NUM		The maximum search depth.\n\
qsize = NUM		The BFS queue size (in bytes).\n\
";

void usage()
{
	printf("%s\n", usage_str);
}

void handle_args(int argc, char **argv)
{
	int c, rc, line_no;
loop:
	c = getopt_long(argc, argv, short_opts, long_opts, NULL);
	switch (c) {
	case -1:
		goto out;
	case 'c':
		rc = n2dassoc_config_load(optarg, &CFG, &line_no);
		if (rc)
			errx(-1, "config load failed, rc: %d, line_no: %d\n",
				rc, line_no);
		break;
	case 'h':
	default:
		usage();
		exit(-1);
		break;
	}
	goto loop;
out:
	;
}

int main(int argc, char **argv)
{
	n2dassoc_t n2dassoc;
	handle_args(argc, argv);

	n2dassoc = n2dassoc_new(&CFG);
	if (!n2dassoc) {
		errx(-1, "n2dassoc_new() failed, errno: %d\n", errno);
	}
	n2dassoc_start(n2dassoc);
	n2dassoc_wait(n2dassoc);
	return 0;
}
#endif
