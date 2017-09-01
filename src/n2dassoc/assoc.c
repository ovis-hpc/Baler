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
 * \file assoc.c
 * \author Narate Taerat (narate at ogc dot us)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "assoc.h"

/*********************************/
/* Private structure definitions */
/*********************************/

/*
 * aq (assoc queue) is a queue containing rule candidates (struct rule_s) of the
 * same size. assoc works with 2 aq's.
 */
typedef struct aq_s {
	uint64_t head_off;
	uint64_t tail_off;
	uint64_t item_size;
	uint64_t data_len;
	uint8_t data[0];
} *aq_t;

typedef struct assoc_thread_s {
	pthread_t pthread;
	assoc_t assoc;
	int id;
	int rc;
	assoc_rule_file_t ar_file;
	union {
		struct assoc_rule_s rule; /* rule buff */
		char _[4096];
	};
} *assoc_thread_t;

#define Q_STATE_READY 0
#define Q_STATE_BUSY 1
#define Q_STATE_DONE 2

typedef struct assoc_s {
	struct assoc_param_s param;
	struct assoc_stat_s stat;
	pthread_mutex_t mutex;
	pthread_cond_t state_cond;
	pthread_cond_t barrier_cond;
	int barr0, barr1;
	int q_state; /* queue state */
	int dirfd;
	aq_t curr_q;
	aq_t next_q;
	assoc_rule_file_t ar_file;
	struct assoc_thread_s threads[0];
} *assoc_t;

#define ODD_Q_FILE "__odd_q"
#define EVEN_Q_FILE "__even_q"

typedef struct assoc_rule_file_hdr_s {
	union {
		struct {
			off_t off;
		};
		char _[4096];
	};
} *assoc_rule_file_hdr_t;

struct assoc_rule_file_hdr_s AR_HDR_INITIALIZER = {.off = 4096};

struct assoc_rule_file_s {
	int fd;
	assoc_rule_file_hdr_t hdr;
	off_t roff; /* read offset relative to mem */
	off_t moff; /* map offset (to file) */
	ssize_t mlen; /* map length */
	void *mem;
	char path[PATH_MAX]; /* for debugging */
};

/*********************/
/* Private Functions */
/*********************/

static inline
size_t __rule_sz(int lhs_n)
{
	return sizeof(struct assoc_rule_s) + lhs_n * sizeof(item_id_t);
}

static
int __ar_file_create(const char *path)
{
	int fd = open(path, O_CREAT|O_EXCL|O_WRONLY|O_TRUNC, 0600);
	ssize_t len;
	if (fd == -1)
		return errno;
	len = write(fd, &AR_HDR_INITIALIZER, sizeof(AR_HDR_INITIALIZER));
	assert(len == sizeof(AR_HDR_INITIALIZER));
	if (len != sizeof(AR_HDR_INITIALIZER))
		return errno;
	return 0;
}

static
assoc_rule_file_t __ar_file_open(const char *path, int flags)
{
	assoc_rule_file_t f;

	f = calloc(1, sizeof(*f));
	if (!f)
		goto err1;

	f->fd = open(path, O_RDWR);
	if (f->fd == -1)
		goto err2;
	f->hdr = mmap(NULL, sizeof(*f->hdr), PROT_READ|PROT_WRITE,
			MAP_SHARED, f->fd, 0);
	if (f->hdr == MAP_FAILED)
		goto err3;
	return f;

err3:
	close(f->fd);
err2:
	free(f);
err1:
	return NULL;
}

static
void __ar_file_close(assoc_rule_file_t f)
{
	if (f->mem)
		munmap(f->mem, f->mlen);
	if (f->hdr)
		munmap(f->hdr, sizeof(*f->hdr));
	if (f->fd != -1)
		close(f->fd);
	free(f);
}

static
int __ar_file_append(assoc_rule_file_t f, assoc_rule_t r)
{
	int rc = 0;
	size_t sz = __rule_sz(r->n);
	off_t off = __sync_fetch_and_add(&f->hdr->off, sz);
	if ((off - f->moff) + sz > f->mlen) {
		/* need a remap */
		off_t moff = off & ~0xFFF; /* 4K page */
		off_t flen = lseek(f->fd, 0, SEEK_END);
		size_t mlen = 0x10000; /* 64 K */
		void *mem;
		if (moff + mlen > flen) {
			/* need file expansion */
			rc = flock(f->fd, LOCK_EX);
			if (rc) {
				rc = errno;
				goto out;
			}
			/* re-check as other thread may have extended */
			flen = lseek(f->fd, 0, SEEK_END);
			if (moff + mlen > flen)
				ftruncate(f->fd, moff + mlen);
			flock(f->fd, LOCK_UN);
		}
		mem = mmap(NULL, mlen, PROT_READ|PROT_WRITE, MAP_SHARED,
			   f->fd, moff);
		if (mem != MAP_FAILED) {
			/* good ==> update */
			if (f->mem)
				munmap(f->mem, f->mlen);
			f->mem = mem;
			f->moff = moff;
			f->mlen = mlen;
		} else {
			rc = errno;
			goto out;
		}
	}
	memcpy(f->mem + (off - f->moff), r, sz);
out:
	return rc;
}

static
int __ar_file_seek(assoc_rule_file_t f, off_t off)
{
	int rc = 0;
	off_t moff = off & ~0xFFF;
	off_t mlen = 0x10000;
	off_t flen = lseek(f->fd, 0, SEEK_END);
	void *mem;
	if (off + mlen > flen) {
		mlen = flen - off;
	}
	mem = mmap(NULL, mlen, PROT_READ|PROT_WRITE, MAP_SHARED, f->fd, moff);
	if (mem == MAP_FAILED) {
		rc = errno;
		goto out;
	}
	if (f->mem)
		munmap(f->mem, f->mlen);
	f->roff = off - moff;
	f->mem = mem;
	f->moff = moff;
	f->mlen = mlen;
out:
	return rc;
}

/* map the entire file */
static
int __ar_file_map_all(assoc_rule_file_t f)
{
	off_t mlen = lseek(f->fd, 0, SEEK_END);
	void *mem;

	mem = mmap(NULL, mlen, PROT_READ|PROT_WRITE, MAP_SHARED, f->fd, 0);
	if (mem == MAP_FAILED)
		return errno;
	if (f->mem)
		munmap(f->mem, f->mlen);
	f->mem = mem;
	f->mlen = mlen;
	f->moff = 0;
	f->roff = sizeof(*f->hdr);
	return 0;
}

static
void __aq_reset(aq_t aq, uint64_t item_sz)
{
	aq->tail_off = aq->head_off = offsetof(struct aq_s, data);
	aq->item_size = item_sz;
}

static
int __aq_add(aq_t aq, const_assoc_rule_t r)
{
	uint64_t off = __sync_fetch_and_add(&aq->tail_off, aq->item_size);
	if (off + aq->item_size >= aq->data_len)
		return ENOMEM;
	memcpy(aq->data + off, r, sizeof(*r) + r->n * sizeof(*r->lhs));
	return 0;
}

static inline
int __aq_is_empty(aq_t aq)
{
	return aq->tail_off == aq->head_off;
}

static
const_assoc_rule_t __aq_remove(aq_t aq)
{
	const_assoc_rule_t a;
	uint64_t off;
	off = __sync_fetch_and_add(&aq->head_off, aq->item_size);
	if (off >= aq->tail_off) {
		errno = ENOENT;
		return NULL;
	}
	a = (void*)aq->data + off;
	return a;
}

static
int __rm_rf_fd(int dfd)
{
	DIR *d;
	int rc;
	struct dirent _ent, *ent;
	struct stat st;
	int flag;
	d = fdopendir(dfd);
	if (!d) {
		rc = errno;
		goto err1;
	}
	rc = readdir_r(d, &_ent, &ent);
	if (rc) {
		/* NOTE: `readdir_r(2)` claims that rc is errno */
		goto err2;
	}
	while (ent) {
		if (strcmp(ent->d_name, ".") == 0)
			goto skip;
		if (strcmp(ent->d_name, "..") == 0)
			goto skip;
		rc = fstatat(dfd, ent->d_name, &st, AT_SYMLINK_NOFOLLOW);
		assert(rc == 0);
		flag = 0;
		if (st.st_mode & S_IFDIR) {
			int _fd = openat(dfd, ent->d_name, O_DIRECTORY|O_RDONLY);
			assert(_fd >= 0);
			__rm_rf_fd(_fd);
			flag = AT_REMOVEDIR;
		}
		unlinkat(dfd, ent->d_name, flag);
skip:
		rc = readdir_r(d, &_ent, &ent);
		if (rc)
			goto err2;
	}
	assert(rc == 0);
	closedir(d);
	return 0;

err2:
	closedir(d);
err1:
	return rc;
}


static
int __rm_rf(const char *path)
{
	int dfd, rc;
	dfd = open(path, O_DIRECTORY|O_RDONLY);
	if (dfd < 0)
		return errno;
	rc = __rm_rf_fd(dfd); /* NOTE: `__rm_rf_fd()` owns dfd */
	if (rc)
		return rc;
	rc = rmdir(path);
	if (rc)
		return errno;
	return 0;
}

static
aq_t __aq_create_at(int dirfd, const char *name, size_t sz)
{
	int fd;
	aq_t aq;
	fd = openat(dirfd, name, O_CREAT|O_EXCL|O_RDWR|O_TRUNC, 0600);
	if (fd < 0)
		goto err1;
	ftruncate(fd, sz);
	aq = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (aq == MAP_FAILED)
		goto err1;
	aq->data_len = sz - offsetof(struct aq_s, data);
	return aq;
err1:
	return NULL;
}

static
void __aq_free(aq_t aq)
{
	munmap(aq, aq->data_len + offsetof(struct aq_s, data));
}

/* caller must have assoc->mutex aquired */
static
int __assoc_barrier_wait(assoc_t assoc, int *barrier)
{
	(*barrier)++;
	pthread_cond_broadcast(&assoc->barrier_cond);
	if (*barrier == assoc->param.threads) {
		return 1;
	}
	while (*barrier < assoc->param.threads) {
		pthread_cond_wait(&assoc->barrier_cond, &assoc->mutex);
	}
	return 0;
}

static
int __assoc_tmpdir_init(assoc_t assoc)
{
	int i, rc;
	struct stat st;
	char buff[128];
	for (i = 0; i < assoc->param.threads; i++) {
		snprintf(buff, sizeof(buff), "thr-%d", i);
		rc = fstatat(assoc->dirfd, buff, &st, 0);
		if (rc) {
			rc = errno;
			if (rc != ENOENT)
				goto err1;
			rc = mkdirat(assoc->dirfd, buff, 0755);
			if (rc) {
				rc = errno;
				goto err1;
			}
			/* success */
			continue;
		}
		/* make sure that it is a directory */
		if (!S_ISDIR(st.st_mode)) {
			errno = rc = EINVAL;
			goto err1;
		}
	}
	return 0;

err1:
	return rc;
}

/********************/
/* Public Functions */
/********************/

assoc_t assoc_new(const_assoc_param_t param)
{
	int rc;
	assoc_t assoc = calloc(1, sizeof(*assoc)
			+ sizeof(assoc->threads[0])*param->threads);
	if (!assoc)
		goto err1;
	assoc->param = *param;
	assoc->dirfd = open(assoc->param.tmp_dir, O_DIRECTORY|O_RDONLY);
	if (assoc->dirfd < 0) {
		rc = mkdir(assoc->param.tmp_dir, 0700);
		if (rc)
			goto err2;
		assoc->dirfd = open(assoc->param.tmp_dir, O_DIRECTORY|O_RDONLY);
		if (assoc->dirfd < 0)
			goto err2;
	}
	rc = __assoc_tmpdir_init(assoc);
	if (rc)
		goto err2;
	if (assoc->param.q_sz == 0) {
		assoc->param.q_sz = 1024*1024*1024;
	}
	assoc->curr_q = __aq_create_at(assoc->dirfd, ODD_Q_FILE,
							assoc->param.q_sz);
	if (!assoc->curr_q)
		goto err2;
	assoc->next_q = __aq_create_at(assoc->dirfd, EVEN_Q_FILE,
							assoc->param.q_sz);
	if (!assoc->next_q)
		goto err2;
	assoc->stat.state = ASSOC_STATE_INIT;
	return assoc;

err2:
	assoc_free(assoc);
err1:
	return NULL;
}

void assoc_free(assoc_t assoc)
{
	if (assoc->curr_q) {
		__aq_free(assoc->curr_q);
		unlinkat(assoc->dirfd, ODD_Q_FILE, 0);
	}
	if (assoc->next_q) {
		__aq_free(assoc->next_q);
		unlinkat(assoc->dirfd, EVEN_Q_FILE, 0);
	}
	if (assoc->dirfd != -1)
		close(assoc->dirfd);
	free(assoc);
}

/*
 * Check if r0 is a redundant rule to r1 (r1 is a more generic rule than r0).
 *
 * \retval 1 if r0 is a redundant to r1
 * \retval 0 otherwise
 */
static inline
int __rule_is_redundant(const_assoc_rule_t r0, const_assoc_rule_t r1)
{
	int i,j;
	if (r0->rhs != r1->rhs)
		return 0;
	i = j = 0;
	while (i < r0->n && j < r1->n) {
		if (r0->lhs[i] == r1->lhs[j]) {
			i++;
			j++;
		} else {
			i++;
		}
	}
	/* r1 exhausted ==> r1 is a subsequence of r0 ==> r0 is a redundant. */
	if (j == r1->n)
		return 1;
	return 0;
}

/*
 * \retval EEXIST if the rule \c r is redundant.
 * \retval 0 if the rule \c r is NOT redundant.
 */
static
int __rule_redundant_check(assoc_t assoc, const_assoc_rule_t r)
{
	off_t off;
	const_assoc_rule_t p;
	if (assoc->ar_file->moff) {
		assert(0 == "Invalid assoc->ar_file");
		return EINVAL;
	}
	off = sizeof(*assoc->ar_file->hdr);
	while (off < assoc->ar_file->mlen) {
		p = assoc->ar_file->mem + off;
		if (p->n >= r->n)
			break;
		if (__rule_is_redundant(r, p))
			return EEXIST;
		off += __rule_sz(p->n);
	}
	return 0;
}

typedef struct assoc_miner_arg_s {
	assoc_t assoc;
	int id;
	int rc;
} *assoc_miner_arg_t;

static
void *__assoc_miner(void *_arg)
{
	int rc;
	int i;
	double supp_x, supp_A, supp_Ab, supp_b;
	aq_t tmp;
	const_assoc_rule_t rule;
	assoc_thread_t thr = _arg;
	assoc_t assoc = thr->assoc;
	struct assoc_support_ctxt_s ctxt;
	thr->rc = 0;

	ctxt.thread_number = thr->id;
	ctxt.arg = assoc->param.arg;

	thr->ar_file = __ar_file_open(assoc->param.ar_path, O_RDWR);
	if (!thr->ar_file) {
		return NULL;
	}

start:
	pthread_mutex_lock(&assoc->mutex);
	rc = __assoc_barrier_wait(assoc, &assoc->barr0);
	if (rc == 1) {
		/* I'm the first guy exiting the barrier with mutex held */
		assoc->barr1 = 0;
	}
	switch (assoc->stat.state) {
	case ASSOC_STATE_BUSY:
		pthread_mutex_unlock(&assoc->mutex);
		goto mine_loop;
	case ASSOC_STATE_FINALIZING:
	case ASSOC_STATE_CANCELLING:
	case ASSOC_STATE_CANCELED:
	case ASSOC_STATE_ERROR:
	case ASSOC_STATE_DONE:
		pthread_mutex_unlock(&assoc->mutex);
		/* no more candidates to process */
		goto out;
	default:
		assert(0 == "Bad queue state");
		thr->rc = EINVAL;
		pthread_mutex_unlock(&assoc->mutex);
		goto out;
	}

mine_loop:
	pthread_testcancel(); /* cancellation point */
	rule = __aq_remove(assoc->curr_q);
	if (!rule)
		goto next_lvl;
	supp_x = assoc->param.support(rule->n, rule->lhs, &ctxt);
	memcpy(&thr->rule, rule, __rule_sz(rule->n));
	thr->rule.n = rule->n + 1;
	thr->rule.lhs[thr->rule.n] = thr->rule.rhs;
	for (i = thr->rule.lhs_last_idx + 1; i < assoc->param.lhs_n; i++) {
		/* bfs */
		thr->rule.lhs[thr->rule.n - 1] = assoc->param.lhs_items[i];
		thr->rule.lhs_last_idx = i;
		__sync_fetch_and_add(&assoc->stat.candidates, 1);

		supp_A = assoc->param.support(thr->rule.n,
					      thr->rule.lhs, &ctxt);
		if (supp_A < 0.000001)
			continue; /* no support */
		if ((supp_x - supp_A) / supp_x < assoc->param.diff)
			continue; /* new candidate add little difference */
		supp_b = assoc->param.support(1, &thr->rule.rhs, &ctxt);
		supp_Ab = assoc->param.support(thr->rule.n + 1,
					       thr->rule.lhs, &ctxt);
		thr->rule.sig = supp_Ab / supp_b;
		if (thr->rule.sig < assoc->param.sig)
			continue; /* sig too low */
		thr->rule.conf = supp_Ab / supp_A;
		if (thr->rule.conf >= assoc->param.conf) {
			/* this is a rule! BUT we need to make sure that the
			 * rule is not a redundant, i.e. there is no simpler
			 * rule prior to this one. */

			rc = __rule_redundant_check(assoc, &thr->rule);
			switch (rc) {
			case EEXIST:
				/* redundant */
				continue;
			case 0:
				/* OK */
				break;
			default:
				/* others */
				thr->rc = rc;
				goto out;
			}
			/* NOT redundant */
			rc = __ar_file_append(thr->ar_file, &thr->rule);
			if (rc) {
				thr->rc = rc;
				goto out;
			}
			__sync_fetch_and_add(&assoc->stat.rules, 1);
			continue;
		}

		/* survive all of the pruning, add the entry into the next q */
		rc = __aq_add(assoc->next_q, &thr->rule);
		if (rc) {
			errno = rc;
			goto out;
		}
	}
	goto mine_loop;

next_lvl:
	pthread_mutex_lock(&assoc->mutex);
	rc = __assoc_barrier_wait(assoc, &assoc->barr1);
	if (rc == 1) {
		/* I'm the first guy exiting the barrier with mutex held */
		assoc->barr0 = 0;
		tmp = assoc->curr_q;
		assoc->curr_q = assoc->next_q;
		assoc->next_q = tmp;
		assoc->stat.depth++;
		__aq_reset(assoc->next_q, __rule_sz(assoc->stat.depth + 1));
		if (__aq_is_empty(assoc->curr_q) ||
				assoc->stat.depth == assoc->param.max_depth) {
			assoc->stat.state = ASSOC_STATE_FINALIZING;
			pthread_cond_broadcast(&assoc->state_cond);
			pthread_mutex_unlock(&assoc->mutex);
			goto start;
		}
		rc = __ar_file_map_all(assoc->ar_file);
		if (rc) {
			thr->rc = rc;
			assoc->stat.state = ASSOC_STATE_FINALIZING;
			pthread_cond_broadcast(&assoc->state_cond);
			pthread_mutex_unlock(&assoc->mutex);
			goto start;
		}
	}
	pthread_mutex_unlock(&assoc->mutex);
	goto start;
out:
	return NULL;
}

static
void __main_miner_cancel(void *arg)
{
	/* For handling the cancellation */
	assoc_t assoc = arg;
	struct assoc_support_ctxt_s ctxt;
	int i, rc;
	for (i = 1; i < assoc->param.threads; i++) {
		pthread_cancel(assoc->threads[i].pthread);
	}
	for (i = 1; i < assoc->param.threads; i++) {
		pthread_join(assoc->threads[i].pthread, NULL);
	}
	pthread_mutex_lock(&assoc->mutex);
	assoc->stat.state = ASSOC_STATE_FINALIZING;
	pthread_cond_broadcast(&assoc->state_cond);
	pthread_mutex_unlock(&assoc->mutex);
	ctxt.thread_number = 0;
	ctxt.arg = assoc->param.arg;
	if (assoc->param.finalize) {
		rc = assoc->param.finalize(&ctxt);
		if (rc) /* so that finalize() rc 0 won't override previous rc */
			assoc->stat.rc = rc;
	}
	pthread_mutex_lock(&assoc->mutex);
	assoc->stat.state = ASSOC_STATE_CANCELED;
	pthread_cond_broadcast(&assoc->state_cond);
	pthread_mutex_unlock(&assoc->mutex);
}

static
void *__main_miner(void *arg)
{
	assoc_t assoc = arg;
	int i, j;
	int rc;
	assoc_rule_t r;
	double supp_A, supp_Ab, supp_b;
	struct assoc_support_ctxt_s ctxt;

	ctxt.thread_number = 0;
	ctxt.arg = assoc->param.arg;

	pthread_cleanup_push(__main_miner_cancel, assoc);

	assoc->stat.depth = 1;
	__aq_reset(assoc->curr_q, __rule_sz(1));
	__aq_reset(assoc->next_q, __rule_sz(2));

	rc = __ar_file_create(assoc->param.ar_path);
	if (rc)
		goto err0;
	assoc->ar_file = __ar_file_open(assoc->param.ar_path, O_RDWR);
	if (!assoc->ar_file) {
		rc = errno;
		goto err0;
	}

	/* Initialize the 1st level here */
	r = &assoc->threads[0].rule;
	r->n = 1;
	for (j = 0; j < assoc->param.rhs_n; j++) {
		r->rhs = assoc->param.rhs_items[j];
		r->lhs[1] = assoc->param.rhs_items[j];
		supp_b = assoc->param.support(1, &r->rhs, &ctxt);
		for (i = 0; i < assoc->param.lhs_n; i++) {
			r->lhs[0] = assoc->param.lhs_items[i];
			r->lhs_last_idx = i;

			__sync_fetch_and_add(&assoc->stat.candidates, 1);

			supp_A = assoc->param.support(1, r->lhs, &ctxt);
			if (supp_A < 0.000001)
				continue; /* no support */
			supp_Ab = assoc->param.support(2, r->lhs, &ctxt);
			r->sig = supp_Ab / supp_b;
			if (r->sig < assoc->param.sig)
				continue; /* sig too low */
			r->conf = supp_Ab / supp_A;
			if (r->conf >= assoc->param.conf) {
				/* A RULE! */
				rc = __ar_file_append(assoc->ar_file, r);
				if (rc)
					goto err0;
				continue;
			}
			/* This is a valid candidate */
			rc = __aq_add(assoc->curr_q, r);
			if (rc)
				goto err0;
		}
	}

	rc = __ar_file_map_all(assoc->ar_file);

	/* miners .. */
	for (i = 1; i < assoc->param.threads; i++) {
		assoc->threads[i].assoc = assoc;
		assoc->threads[i].id = i;
		assoc->threads[i].rc = 0;
		rc = pthread_create(&assoc->threads[i].pthread, NULL,
				    __assoc_miner, &assoc->threads[i]);
		if (rc)
			goto err1;
	}

	assoc->threads[0].assoc = assoc;
	assoc->threads[0].id = 0;
	assoc->threads[0].rc = 0;
	__assoc_miner(&assoc->threads[0]); /* main miner also participate in the
					      mining routine */

	for (i = 1; i < assoc->param.threads; i++) {
		pthread_join(assoc->threads[i].pthread, NULL);
	}
	/* reaching here means completed .. could be a success or a failure */

	pthread_mutex_lock(&assoc->mutex);
	assoc->stat.rc = 0;
	for (i = 0; i < assoc->param.threads; i++) {
		if (assoc->threads[i].rc) {
			assoc->stat.rc = rc;
			break;
		}
	}
	assoc->stat.state = ASSOC_STATE_FINALIZING;
	pthread_cond_broadcast(&assoc->state_cond);
	pthread_mutex_unlock(&assoc->mutex);
	goto out;

err1:
	i--;
	while (i > 0) {
		pthread_cancel(assoc->threads[i].pthread);
	}
	__ar_file_close(assoc->ar_file);
err0:
	assoc->stat.rc = rc;
out:
	pthread_cleanup_pop(0);

	/* finalizing */
	ctxt.thread_number = 0;
	ctxt.arg = assoc->param.arg;
	if (assoc->param.finalize) {
		rc = assoc->param.finalize(&ctxt);
		if (rc) /* so that finalize() rc 0 won't override previous rc */
			assoc->stat.rc = rc;
	}

	/* done! */
	pthread_mutex_lock(&assoc->mutex);
	assoc->stat.state = assoc->stat.rc?ASSOC_STATE_ERROR:ASSOC_STATE_DONE;
	pthread_cond_broadcast(&assoc->state_cond);
	pthread_mutex_unlock(&assoc->mutex);
	return NULL;
}

int assoc_mine(assoc_t assoc)
{
	int rc = 0;
	pthread_mutex_lock(&assoc->mutex);
	if (assoc->stat.state != ASSOC_STATE_INIT) {
		rc = EINVAL;
		goto out;
	}
	assoc->stat.state = ASSOC_STATE_BUSY;
	pthread_cond_broadcast(&assoc->state_cond);
	rc = pthread_create(&assoc->threads[0].pthread,
			    NULL, __main_miner, assoc);
	if (rc) {
		assoc->stat.state = ASSOC_STATE_ERROR;
		pthread_cond_broadcast(&assoc->state_cond);
		assoc->stat.rc = rc;
	}
out:
	pthread_mutex_unlock(&assoc->mutex);
	return rc;
}

int assoc_stat(assoc_t assoc, assoc_stat_t stat)
{
	pthread_mutex_lock(&assoc->mutex);
	*stat = assoc->stat;
	pthread_mutex_unlock(&assoc->mutex);
	return 0;
}

int assoc_stat_print(FILE *stream, const assoc_stat_t stat)
{
	const char *state;
	switch (stat->state) {
	case ASSOC_STATE_INIT:
		state = "ASSOC_STATE_INIT";
		break;
	case ASSOC_STATE_DONE:
		state = "ASSOC_STATE_DONE";
		break;
	case ASSOC_STATE_BUSY:
		state = "ASSOC_STATE_BUSY";
		break;
	case ASSOC_STATE_ERROR:
		state = "ASSOC_STATE_ERROR";
		break;
	case ASSOC_STATE_CANCELLING:
		state = "ASSOC_STATE_CANCELLING";
		break;
	case ASSOC_STATE_CANCELED:
		state = "ASSOC_STATE_CANCELED";
		break;
	case ASSOC_STATE_FINALIZING:
		state = "ASSOC_STATE_FINALIZING";
		break;
	default:
		state = "(INVALID)";
		break;
	}
	return fprintf(stream,
			"stat{ state: %s, rc: %d, depth: %d, rules: %lu, "
			"candidates: %lu }\n",
			state,
			stat->rc,
			stat->depth,
			stat->rules,
			stat->candidates);
}

int assoc_wait(assoc_t assoc)
{
	pthread_mutex_lock(&assoc->mutex);
again:
	switch (assoc->stat.state) {
	case ASSOC_STATE_ERROR:
	case ASSOC_STATE_CANCELED:
	case ASSOC_STATE_DONE:
		break;
	case ASSOC_STATE_INIT:
	case ASSOC_STATE_BUSY:
	case ASSOC_STATE_CANCELLING:
	case ASSOC_STATE_FINALIZING:
		pthread_cond_wait(&assoc->state_cond, &assoc->mutex);
		goto again;
	default:
		assert(0 == "Bad assoc state");
	}
	pthread_mutex_unlock(&assoc->mutex);
	return assoc->stat.rc;
}

assoc_rule_file_t assoc_rule_file_open(const char *path)
{
	return __ar_file_open(path, O_RDONLY);
}

void assoc_rule_file_close(assoc_rule_file_t ar_file)
{
	__ar_file_close(ar_file);
}

const_assoc_rule_t assoc_rule_file_read(assoc_rule_file_t ar_file)
{
	int rc;
	size_t sz;
	const_assoc_rule_t r = NULL;
	if (ar_file->roff + ar_file->moff >= ar_file->hdr->off) {
		/* no more rules */
		errno = ENOENT;
		return NULL;
	}
	if (ar_file->roff + sizeof(struct assoc_rule_s) > ar_file->mlen) {
		rc = __ar_file_seek(ar_file, ar_file->moff + ar_file->roff);
		if (rc)
			return NULL; /* errno has been set in __ar_file_seek */
	}
	r = ar_file->mem + ar_file->roff;
	sz = __rule_sz(r->n);
	if (ar_file->roff + sz > ar_file->mlen) {
		rc = __ar_file_seek(ar_file, ar_file->moff + ar_file->roff);
		if (rc)
			return NULL; /* errno has been set in __ar_file_seek */
	}
	r = ar_file->mem + ar_file->roff;
	ar_file->roff += sz;
	return r;
}

void assoc_rule_file_dump(FILE *stream, assoc_rule_file_t ar_file, int hex)
{
	const_assoc_rule_t r;
	int rc, len;

	rc = __ar_file_seek(ar_file, sizeof(*ar_file->hdr));
	assert(rc == 0);
	while ((r = assoc_rule_file_read(ar_file))) {
		len = assoc_rule_print(stream, r, hex);
		assert(len>0);
	}
}

int assoc_rule_print(FILE *stream, const_assoc_rule_t r, int hex)
{
	int sum_len = 0;
	int len = 0;
	int i;
	len = fprintf(stream, "(conf: %lf, sig: %lf)", r->conf, r->sig);
	if (len < 0)
		return -1;
	sum_len += len;
	if (hex)
		len = fprintf(stream, "{%#lx", r->lhs[0]);
	else
		len = fprintf(stream, "{%lu", r->lhs[0]);
	if (len < 0)
		return -1;
	sum_len += len;
	for (i = 1; i < r->n; i++) {
		if (hex)
			len = fprintf(stream, ", %#lx", r->lhs[i]);
		else
			len = fprintf(stream, ", %lu", r->lhs[i]);
		if (len < 0)
			return -1;
		sum_len += len;
	}
	if (hex)
		len = fprintf(stream, "}==>{%#lx}\n", r->rhs);
	else
		len = fprintf(stream, "}==>{%lu}\n", r->rhs);
	if (len < 0)
		return -1;
	sum_len += len;
	return sum_len;
}

int assoc_rule_file_verify(assoc_rule_file_t ar_file)
{
	int rc;
	off_t off0, off1;
	const_assoc_rule_t r0, r1;
	rc = __ar_file_map_all(ar_file);
	if (rc)
		return rc;
	off0 = sizeof(*ar_file->hdr);
	while (off0 < ar_file->hdr->off) {
		r0 = ar_file->mem + off0;
		off1 = sizeof(*ar_file->hdr);
		while (off1 < off0) {
			r1 = ar_file->mem + off1;
			if (__rule_is_redundant(r0, r1))
				return EINVAL;
			off1 += __rule_sz(r1->n);
		}
		off0 += __rule_sz(r0->n);
	}
	return 0;
}

int assoc_cancel(assoc_t assoc)
{
	int rc;
	pthread_mutex_lock(&assoc->mutex);
	if (assoc->stat.state != ASSOC_STATE_BUSY) {
		rc = EINVAL;
		goto out;
	}
	assoc->stat.state = ASSOC_STATE_CANCELLING;
	pthread_cond_broadcast(&assoc->state_cond);
	pthread_cancel(assoc->threads[0].pthread);
	rc = 0;
out:
	pthread_mutex_unlock(&assoc->mutex);
	return rc;
}

int assoc_rule_foreach(assoc_t assoc,
		       int (*cb)(const_assoc_rule_t rule, void *arg),
		       void *arg)
{
	int rc;
	off_t off;
	const_assoc_rule_t r;
	rc = __ar_file_map_all(assoc->ar_file);
	if (rc)
		goto out;
	off = sizeof(*assoc->ar_file->hdr);
	while (off < assoc->ar_file->hdr->off) {
		r = assoc->ar_file->mem + off;
		rc = cb(r, arg);
		if (rc)
			goto out;
		off += __rule_sz(r->n);
	}
out:
	return rc;
}
