/**
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "bhash_u.h"
#include "fnv_hash.h"
#include <sys/types.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <pthread.h>
#include <errno.h>

typedef struct bhash_u_s *bhash_u_t;

struct bhash_u_entry_s {
	bhash_u_key_t key;
	bhash_u_value_t value;
};

static inline
size_t BHASH_U_MAP_SZ(size_t len)
{
	size_t sz = len * sizeof(struct bhash_u_entry_s);
	sz = ((sz - 1)|0xFFF) + 1;
	return sz;
}

struct bhash_u_s {
	size_t len; /* entry array length in number of elements */
	size_t n; /* number of occupied entries */
	pthread_mutex_t mutex;
	struct bhash_u_entry_s *entry;
};

bhash_u_t bhash_u_new(int htbl_size)
{
	size_t sz;
	bhash_u_t h;

	h = calloc(1, sizeof(*h));
	if (!h)
		return NULL;
	h->len = htbl_size;
	sz = BHASH_U_MAP_SZ(h->len);
	h->entry = mmap(NULL, sz, PROT_READ|PROT_WRITE,
			MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (h->entry == MAP_FAILED)
		return NULL;
	pthread_mutex_init(&h->mutex, NULL);
	return h;
}

void bhash_u_free(bhash_u_t h)
{
	if (h->entry != MAP_FAILED)
		munmap(h->entry, BHASH_U_MAP_SZ(h->len));
	free(h);
}

int bhash_u_insert(bhash_u_t h, bhash_u_value_t value, bhash_u_key_t *key_out)
{
	bhash_u_key_t key;
	int idx;
	int rc;
	struct {
		struct timeval tv;
		bhash_u_value_t value;
	} data;

	pthread_mutex_lock(&h->mutex);
	if (h->n == h->len) {
		rc = ENOMEM;
		goto out;
	}
	gettimeofday(&data.tv, NULL);
again:
	key = fnv_hash_a1_64((void*)&data, sizeof(data), 0);
	idx = key % h->len;
	if (!key || h->entry[idx].key) {
		/* key must not be 0, and h->entry[idx] must not be occupied */
		data.tv.tv_usec += 1;
		goto again;
	}
	h->entry[idx].key = key;
	h->entry[idx].value = value;
	h->n++;
	*key_out = key;
	rc = 0;
out:
	pthread_mutex_unlock(&h->mutex);
	return rc;
}

int bhash_u_remove(bhash_u_t h, bhash_u_key_t k)
{
	int idx;
	int rc;

	pthread_mutex_lock(&h->mutex);
	idx = k % h->len;
	if (h->entry[idx].key != k) {
		rc = ENOENT;
		goto out;
	}
	h->entry[idx].key = 0;
	h->entry[idx].value = 0;
	rc = 0;
out:
	pthread_mutex_unlock(&h->mutex);
	return rc;
}

int bhash_u_remove2(bhash_u_t h, bhash_u_key_t k, bhash_u_value_t *value_out)
{
	int idx;
	int rc;

	pthread_mutex_lock(&h->mutex);
	idx = k % h->len;
	if (h->entry[idx].key != k) {
		rc = ENOENT;
		goto out;
	}
	*value_out = h->entry[idx].value;
	h->entry[idx].key = 0;
	h->entry[idx].value = 0;
	rc = 0;
out:
	pthread_mutex_unlock(&h->mutex);
	return rc;
}

int bhash_u_get(bhash_u_t h, bhash_u_key_t key, bhash_u_value_t *value_out)
{
	int rc;
	int idx;

	pthread_mutex_lock(&h->mutex);
	idx = key % h->len;
	if (h->entry[idx].key != key) {
		rc = ENOENT;
		goto out;
	}
	*value_out = h->entry[idx].value;
	rc = 0;
out:
	pthread_mutex_unlock(&h->mutex);
	return rc;
}

int bhash_u_resize(bhash_u_t h, int new_htbl_size)
{
	int rc;
	int i;
	int idx;
	struct bhash_u_entry_s *entry;

	pthread_mutex_lock(&h->mutex);
	entry = mmap(NULL, BHASH_U_MAP_SZ(new_htbl_size), PROT_READ|PROT_WRITE,
		     MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (entry == MAP_FAILED) {
		rc = errno;
		goto out;
	}
	for (i = 0; i < h->len; i++) {
		if (!h->entry[i].key)
			continue;
		idx = h->entry[i].key % new_htbl_size;
		if (entry[idx].key) {
			/* entry collide .. cannot resize with this size */
			munmap(entry, BHASH_U_MAP_SZ(new_htbl_size));
			rc = EINVAL;
			goto out;
		}
		entry[idx] = h->entry[i];
	}
	munmap(h->entry, BHASH_U_MAP_SZ(h->len));
	h->entry = entry;
	rc = 0;
out:
	pthread_mutex_unlock(&h->mutex);
	return rc;
}
