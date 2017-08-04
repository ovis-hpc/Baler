#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <limits.h>
#include "rbt.h"
#include "bstore.h"
#include "butils.h"
#include <stdarg.h>
#include <pthread.h>
#include <assert.h>
#include <sys/time.h>
#include "fnv_hash.h"

#ifdef DEBUG_BLEN
#  define BLEN_ASSERT(bstr) assert(strlen((bstr)->cstr) == (bstr)->blen)
#  define STRLEN_ASSERT(str, len) assert(strlen(str)==len)
#else
#  define BLEN_ASSERT(bstr) /* noop */
#  define STRLEN_ASSERT(str, len) /* noop */
#endif

struct pos_handle_entry {
	struct rbn rbn;
	bstore_iter_pos_handle_t handle;
	bstore_iter_pos_t pos;
};

struct plugin_entry {
	bstore_plugin_t plugin;
	struct rbn rbn;
};

pthread_mutex_t plugin_lock;
static int plugin_cmp(const void *a, const void *b)
{
	return strcmp(a, b);
}

struct rbt plugin_tree = RBT_INITIALIZER(plugin_cmp);

static bstore_plugin_t __get_plugin(const char *name)
{
	struct plugin_entry *pe;
	char *plugin_path;
	char *plugin_dir;
	bstore_plugin_t plugin;
	struct rbn *rbn;
	void *dl;
	bstore_init_fn_t get_plugin;

	pthread_mutex_lock(&plugin_lock);
	rbn = rbt_find(&plugin_tree, name);
	if (rbn) {
		pe = container_of(rbn, struct plugin_entry, rbn);
		plugin = pe->plugin;
		goto out;
	}
	plugin_dir = getenv("BSTORE_PLUGIN_PATH");
	if (!plugin_dir) {
		berror("The BSTORE_PLUGIN_PATH environment variable must be set.");
		errno = EINVAL;
		goto err_0;
	}
	plugin_path = malloc(PATH_MAX);
	if (!plugin_path)
		goto err_0;
	sprintf(plugin_path, "%s/lib%s.so", plugin_dir, name);
	dl = dlopen(plugin_path, RTLD_NOW);
	if (!dl) {
		char *err_str = dlerror();
		if (err_str)
			berror(err_str);
		errno = EINVAL;
		goto err_1;
	}
	get_plugin = dlsym(dl, "get_plugin");
	if (!get_plugin)
		goto err_2;
	pe = malloc(sizeof *pe);
	if (!pe)
		goto err_2;
	plugin = get_plugin();
	if (!plugin)
		goto err_3;
	pe->plugin = plugin;
	rbn_init(&pe->rbn, (char *)name);
	rbt_ins(&plugin_tree, &pe->rbn);
	free(plugin_path);
 out:
	pthread_mutex_unlock(&plugin_lock);
	return plugin;
 err_3:
	free(pe);
 err_2:
	dlclose(dl);
 err_1:
	free(plugin_path);
 err_0:
	pthread_mutex_unlock(&plugin_lock);
	return NULL;
}

static
int __int_cmp(void *_a, void *_b)
{
	uint32_t a = *(uint32_t*)_a;
	uint32_t b = *(uint32_t*)_b;
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

static int pos_handle_cmp(const void *a, const void *b)
{
	const bstore_iter_pos_handle_t *ha = a;
	const bstore_iter_pos_handle_t *hb = b;
	if (*ha < *hb)
		return -1;
	if (*ha > *hb)
		return 1;
	return 0;
}

bstore_t bstore_open(const char *name, const char *path, int flags, ...)
{
	bstore_t store = NULL;
	va_list ap;
	int o_mode;
	struct rbt *pos_rbt;
	bstore_plugin_t plugin = __get_plugin(name);
	if (!plugin)
		return NULL;
	pos_rbt = calloc(1, sizeof(*pos_rbt));
	if (!pos_rbt)
		return NULL;
	rbt_init(pos_rbt, pos_handle_cmp);
	va_start(ap, flags);
	o_mode = va_arg(ap, int);
	store = plugin->open(plugin, path, flags, o_mode);
	if (!store) {
		free(pos_rbt);
		return NULL;
	}
	store->pos_rbt = pos_rbt;
	return store;
}

void bstore_close(bstore_t bs)
{
	free(bs->pos_rbt);
	bs->plugin->close(bs);
}

btkn_id_t bstore_tkn_add(bstore_t bs, btkn_t tkn)
{
	BLEN_ASSERT(tkn->tkn_str);
	return bs->plugin->tkn_add(bs, tkn);
}

int bstore_tkn_add_with_id(bstore_t bs, btkn_t tkn)
{
	return bs->plugin->tkn_add_with_id(bs, tkn);
}

btkn_t bstore_tkn_find_by_id(bstore_t bs, btkn_id_t tkn_id)
{
	return bs->plugin->tkn_find_by_id(bs, tkn_id);
}

btkn_t bstore_tkn_find_by_name(bstore_t bs, const char *text, size_t text_len)
{
	STRLEN_ASSERT(text, text_len);
	return bs->plugin->tkn_find_by_name(bs, text, text_len);
}

bstore_iter_pos_handle_t bstore_tkn_iter_pos_get(btkn_iter_t iter)
{
	return bstore_iter_pos_get(iter);
}

int bstore_tkn_iter_pos_set(btkn_iter_t iter, bstore_iter_pos_handle_t pos_h)
{
	return bstore_iter_pos_set(iter, pos_h);
}

btkn_iter_t bstore_tkn_iter_new(bstore_t bs)
{
	return bs->plugin->tkn_iter_new(bs);
}

void bstore_tkn_iter_free(btkn_iter_t iter)
{
	iter->bs->plugin->tkn_iter_free(iter);
}

uint64_t bstore_tkn_iter_card(btkn_iter_t iter)
{
	return iter->bs->plugin->tkn_iter_card(iter);
}

int bstore_tkn_iter_first(btkn_iter_t iter)
{
	return iter->bs->plugin->tkn_iter_first(iter);
}

btkn_t bstore_tkn_iter_obj(btkn_iter_t iter)
{
	return iter->bs->plugin->tkn_iter_obj(iter);
}

int bstore_tkn_iter_next(btkn_iter_t iter)
{
	return iter->bs->plugin->tkn_iter_next(iter);
}

int bstore_tkn_iter_prev(btkn_iter_t iter)
{
	return iter->bs->plugin->tkn_iter_prev(iter);
}

int bstore_tkn_iter_last(btkn_iter_t iter)
{
	return iter->bs->plugin->tkn_iter_last(iter);
}

bstore_iter_pos_handle_t bstore_ptn_iter_pos_get(bptn_iter_t iter)
{
	return bstore_iter_pos_get(iter);
}

int bstore_ptn_iter_pos_set(bptn_iter_t iter, bstore_iter_pos_handle_t pos_h)
{
	return bstore_iter_pos_set(iter, pos_h);
}

bptn_iter_t bstore_ptn_iter_new(bstore_t bs)
{
	return bs->plugin->ptn_iter_new(bs);
}

void bstore_ptn_iter_free(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_free(iter);
}

int bstore_ptn_iter_filter_set(bptn_iter_t iter, bstore_iter_filter_t filter)
{
	return iter->bs->plugin->ptn_iter_filter_set(iter, filter);
}

uint64_t bstore_ptn_iter_card(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_card(iter);
}

int bstore_ptn_iter_find_fwd(bptn_iter_t iter, bptn_id_t ptn_id)
{
	return iter->bs->plugin->ptn_iter_find_fwd(iter, ptn_id);
}

int bstore_ptn_iter_find_rev(bptn_iter_t iter, bptn_id_t ptn_id)
{
	return iter->bs->plugin->ptn_iter_find_rev(iter, ptn_id);
}

bptn_t bstore_ptn_iter_obj(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_obj(iter);
}

int bstore_ptn_iter_next(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_next(iter);
}

int bstore_ptn_iter_prev(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_prev(iter);
}

int bstore_ptn_iter_first(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_first(iter);
}

int bstore_ptn_iter_last(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_last(iter);
}

bptn_id_t bstore_ptn_add(bstore_t bs, struct timeval *tv, bstr_t ptn)
{
	return bs->plugin->ptn_add(bs, tv, ptn);
}

bptn_t bstore_ptn_find(bstore_t bs, bptn_id_t ptn_id)
{
	return bs->plugin->ptn_find(bs, ptn_id);
}

int bstore_ptn_find_by_ptnstr(bstore_t bs, bptn_t ptn)
{
	return bs->plugin->ptn_find_by_ptnstr(bs, ptn);
}

int bstore_msg_add(bstore_t bs, struct timeval *tv, bmsg_t msg)
{
	return bs->plugin->msg_add(bs, tv, msg);
}

bstore_iter_pos_handle_t bstore_msg_iter_pos_get(bmsg_iter_t iter)
{
	return bstore_iter_pos_get(iter);
}

bmsg_iter_t bstore_msg_iter_new(bstore_t bs)
{
	return bs->plugin->msg_iter_new(bs);
}

void bstore_msg_iter_free(bmsg_iter_t iter)
{
	iter->bs->plugin->msg_iter_free(iter);
}

uint64_t bstore_msg_iter_card(bmsg_iter_t iter)
{
	return iter->bs->plugin->msg_iter_card(iter);
}

/**
 * Return the first message matching message
 *
 * The messages are ordered first by ptn_id, then by time, then by
 * component id. The <tt>ptn_id</tt> and <tt>start</tt> parameters
 * will position the iterator at the first matrching message. If the
 * cmp_fn() parameter is specified, it will be called with the message
 * attributes to determine if the message matches. If it matches, it
 * will be returned, otherwise, it will be skipped. If the cmp_fn()
 * parameter is null, each message following the first match will be
 * returned and the caller will need to determine whether or not to
 * skip the message.
 *
 * \param iter	 The iterator handle returned by bstore_msg_iter_new()
 * \param ptn_id The pattern that the message matches or 0 for any pattern
 * \param start  The start time as a Unix timestamp, or zero for any
 * \param cmp_fn A comparator function for candidate messages in the
 *               iterator. See the bstore_msg_cmp_fn_t() function
 *               for more details.
 * \param ctxt   A context parameter that will be passed to the cmp_fn()
 *               for each candidate message
 * \retval A bmsg_t or NULL if not found.
 */
int bstore_msg_iter_find_fwd(bmsg_iter_t iter, const struct timeval *tv,
			     bcomp_id_t comp_id, bptn_id_t ptn_id)
{
	return iter->bs->plugin->msg_iter_find_fwd(iter, tv, comp_id, ptn_id);
}

int bstore_msg_iter_find_rev(bmsg_iter_t iter, const struct timeval *tv,
			     bcomp_id_t comp_id, bptn_id_t ptn_id)
{
	return iter->bs->plugin->msg_iter_find_rev(iter, tv, comp_id, ptn_id);
}

int bstore_msg_iter_pos_set(bmsg_iter_t iter, bstore_iter_pos_handle_t pos_h)
{
	return bstore_iter_pos_set(iter, pos_h);
}

bmsg_t bstore_msg_iter_obj(bmsg_iter_t iter)
{
	return iter->bs->plugin->msg_iter_obj(iter);
}

int bstore_msg_iter_first(bmsg_iter_t iter)
{
	return iter->bs->plugin->msg_iter_first(iter);
}

int bstore_msg_iter_next(bmsg_iter_t iter)
{
	return iter->bs->plugin->msg_iter_next(iter);
}

int bstore_msg_iter_prev(bmsg_iter_t iter)
{
	return iter->bs->plugin->msg_iter_prev(iter);
}

int bstore_msg_iter_last(bmsg_iter_t iter)
{
	return iter->bs->plugin->msg_iter_last(iter);
}

int bstore_msg_iter_filter_set(bmsg_iter_t iter, bstore_iter_filter_t filter)
{
	return iter->bs->plugin->msg_iter_filter_set(iter, filter);
}

bstore_iter_pos_handle_t bstore_ptn_tkn_iter_pos_get(bptn_tkn_iter_t iter)
{
	return bstore_iter_pos_get(iter);
}

int bstore_ptn_tkn_iter_pos_set(bptn_tkn_iter_t iter,
				bstore_iter_pos_handle_t pos_h)
{
	return bstore_iter_pos_set(iter, pos_h);
}

bptn_tkn_iter_t bstore_ptn_tkn_iter_new(bstore_t bs)
{
	return bs->plugin->ptn_tkn_iter_new(bs);
}

void bstore_ptn_tkn_iter_free(bptn_tkn_iter_t iter)
{
	iter->bs->plugin->ptn_tkn_iter_free(iter);
}

uint64_t bstore_ptn_tkn_iter_card(bptn_tkn_iter_t iter)
{
	return iter->bs->plugin->ptn_tkn_iter_card(iter);
}

btkn_t bstore_ptn_tkn_iter_obj(bptn_tkn_iter_t iter)
{
	return iter->bs->plugin->ptn_tkn_iter_obj(iter);
}

int bstore_ptn_tkn_iter_first(bptn_tkn_iter_t iter)
{
	return iter->bs->plugin->ptn_tkn_iter_first(iter);
}

int bstore_ptn_tkn_iter_next(bptn_tkn_iter_t iter)
{
	return iter->bs->plugin->ptn_tkn_iter_next(iter);
}

int bstore_ptn_tkn_iter_prev(bptn_tkn_iter_t iter)
{
	return iter->bs->plugin->ptn_tkn_iter_prev(iter);
}

int bstore_ptn_tkn_iter_last(bptn_tkn_iter_t iter)
{
	return iter->bs->plugin->ptn_tkn_iter_last(iter);
}

int bstore_ptn_tkn_iter_filter_set(bptn_tkn_iter_t iter,
				   bstore_iter_filter_t filter)
{
	return iter->bs->plugin->ptn_tkn_iter_filter_set(iter, filter);
}

btkn_type_t bstore_tkn_type_get(bstore_t bs, const char *name, size_t len)
{
	return bs->plugin->tkn_type_get(bs, name, len);
}

int bstore_tkn_hist_update(bstore_t bs, time_t sec, time_t bin_width, btkn_id_t tkn_id)
{
	return bs->plugin->tkn_hist_update(bs, sec, bin_width, tkn_id);
}

bstore_iter_pos_handle_t bstore_tkn_hist_iter_pos_get(btkn_hist_iter_t iter)
{
	return bstore_iter_pos_get(iter);
}

int bstore_tkn_hist_iter_pos_set(btkn_hist_iter_t iter,
				 bstore_iter_pos_handle_t pos_h)
{
	return bstore_iter_pos_set(iter, pos_h);
}

int bstore_tkn_hist_iter_filter_set(btkn_hist_iter_t iter,
				    bstore_iter_filter_t filter)
{
	return iter->bs->plugin->tkn_hist_iter_filter_set(iter, filter);
}

btkn_hist_iter_t bstore_tkn_hist_iter_new(bstore_t bs)
{
	return bs->plugin->tkn_hist_iter_new(bs);
}

void bstore_tkn_hist_iter_free(btkn_hist_iter_t i)
{
	i->bs->plugin->tkn_hist_iter_free(i);
}

int bstore_tkn_hist_iter_find_fwd(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	return iter->bs->plugin->tkn_hist_iter_find_fwd(iter, tkn_h);
}

int bstore_tkn_hist_iter_find_rev(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	return iter->bs->plugin->tkn_hist_iter_find_rev(iter, tkn_h);
}

btkn_hist_t bstore_tkn_hist_iter_obj(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	return iter->bs->plugin->tkn_hist_iter_obj(iter, tkn_h);
}

int bstore_tkn_hist_iter_next(btkn_hist_iter_t iter)
{
	return iter->bs->plugin->tkn_hist_iter_next(iter);
}

int bstore_tkn_hist_iter_prev(btkn_hist_iter_t iter)
{
	return iter->bs->plugin->tkn_hist_iter_prev(iter);
}

int bstore_tkn_hist_iter_first(btkn_hist_iter_t iter)
{
	return iter->bs->plugin->tkn_hist_iter_first(iter);
}

int bstore_tkn_hist_iter_last(btkn_hist_iter_t iter)
{
	return iter->bs->plugin->tkn_hist_iter_last(iter);
}

int bstore_ptn_hist_update(bstore_t bs, bptn_id_t ptn_id, bcomp_id_t comp_id,
			   time_t secs, time_t bin_width)
{
	return bs->plugin->ptn_hist_update(bs, ptn_id, comp_id, secs, bin_width);
}

int bstore_ptn_tkn_add(bstore_t bs, bptn_id_t ptn_id, uint64_t tkn_pos, btkn_id_t tkn_id)
{
	return bs->plugin->ptn_tkn_add(bs, ptn_id, tkn_pos, tkn_id);
}

btkn_t bstore_ptn_tkn_find(bstore_t bs, bptn_id_t ptn_id,
			   uint64_t tkn_pos, btkn_id_t tkn_id)
{
	return bs->plugin->ptn_tkn_find(bs, ptn_id, tkn_pos, tkn_id);
}

bstore_iter_pos_handle_t bstore_ptn_hist_iter_pos_get(bptn_hist_iter_t iter)
{
	return bstore_iter_pos_get(iter);
}

int bstore_ptn_hist_iter_pos_set(bptn_hist_iter_t iter,
				 bstore_iter_pos_handle_t pos_h)
{
	return bstore_iter_pos_set(iter, pos_h);
}

bptn_hist_iter_t bstore_ptn_hist_iter_new(bstore_t bs)
{
	return bs->plugin->ptn_hist_iter_new(bs);
}

void bstore_ptn_hist_iter_free(bptn_hist_iter_t i)
{
	i->bs->plugin->ptn_hist_iter_free(i);
}

int bstore_ptn_hist_iter_find_fwd(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	return iter->bs->plugin->ptn_hist_iter_find_fwd(iter, ptn_h);
}

int bstore_ptn_hist_iter_find_rev(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	return iter->bs->plugin->ptn_hist_iter_find_rev(iter, ptn_h);
}

bptn_hist_t bstore_ptn_hist_iter_obj(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	return iter->bs->plugin->ptn_hist_iter_obj(iter, ptn_h);
}

int bstore_ptn_hist_iter_filter_set(btkn_hist_iter_t iter,
				    bstore_iter_filter_t filter)
{
	return iter->bs->plugin->ptn_hist_iter_filter_set(iter, filter);
}

int bstore_ptn_hist_iter_first(bptn_hist_iter_t iter)
{
	return iter->bs->plugin->ptn_hist_iter_first(iter);
}

int bstore_ptn_hist_iter_next(bptn_hist_iter_t iter)
{
	return iter->bs->plugin->ptn_hist_iter_next(iter);
}

int bstore_ptn_hist_iter_prev(bptn_hist_iter_t iter)
{
	return iter->bs->plugin->ptn_hist_iter_prev(iter);
}

int bstore_ptn_hist_iter_last(bptn_hist_iter_t iter)
{
	return iter->bs->plugin->ptn_hist_iter_last(iter);
}

bstore_iter_pos_handle_t bstore_comp_hist_iter_pos_get(bcomp_hist_iter_t iter)
{
	return bstore_iter_pos_get(iter);
}

int bstore_comp_hist_iter_pos_set(bcomp_hist_iter_t iter,
				  bstore_iter_pos_handle_t pos_h)
{
	return bstore_iter_pos_set(iter, pos_h);
}

bcomp_hist_iter_t bstore_comp_hist_iter_new(bstore_t bs)
{
	return bs->plugin->comp_hist_iter_new(bs);
}

void bstore_comp_hist_iter_free(bcomp_hist_iter_t i)
{
	i->bs->plugin->comp_hist_iter_free(i);
}

int bstore_comp_hist_iter_find_fwd(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	return iter->bs->plugin->comp_hist_iter_find_fwd(iter, comp_h);
}

int bstore_comp_hist_iter_find_rev(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	return iter->bs->plugin->comp_hist_iter_find_rev(iter, comp_h);
}

bcomp_hist_t bstore_comp_hist_iter_obj(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	return iter->bs->plugin->comp_hist_iter_obj(iter, comp_h);
}

int bstore_comp_hist_iter_filter_set(btkn_hist_iter_t iter,
				     bstore_iter_filter_t filter)
{
	return iter->bs->plugin->comp_hist_iter_filter_set(iter, filter);
}

int bstore_comp_hist_iter_next(bcomp_hist_iter_t iter)
{
	return iter->bs->plugin->comp_hist_iter_next(iter);
}

int bstore_comp_hist_iter_prev(bcomp_hist_iter_t iter)
{
	return iter->bs->plugin->comp_hist_iter_prev(iter);
}

int bstore_comp_hist_iter_first(bcomp_hist_iter_t iter)
{
	return iter->bs->plugin->comp_hist_iter_first(iter);
}

int bstore_comp_hist_iter_last(bcomp_hist_iter_t iter)
{
	return iter->bs->plugin->comp_hist_iter_last(iter);
}

rbt_visit_action_t __pos_get_cb(struct rbn *rbn, const void *key, void *cb_arg,
				struct rbn **new_rbn)
{
	struct pos_handle_entry *ent = cb_arg;
	bstore_iter_pos_handle_t handle = *(bstore_iter_pos_handle_t*)key;
	if (rbn) {
		/* pos_handle collides */
		ent->handle = 0;
		return RBT_VISIT_ACTION_NOOP;
	}

	ent->handle = *(bstore_iter_pos_handle_t*)key;
	*new_rbn = &ent->rbn;
	return RBT_VISIT_ACTION_INS;
}

static
void __bstore_iter_pos_free(bstore_iter_t iter, bstore_iter_pos_t pos)
{
	switch (pos->type) {
	case BTKN_ITER:
		iter->bs->plugin->tkn_iter_pos_free(iter, pos);
		break;
	case BMSG_ITER:
		iter->bs->plugin->msg_iter_pos_free(iter, pos);
		break;
	case BPTN_ITER:
		iter->bs->plugin->ptn_iter_pos_free(iter, pos);
		break;
	case BPTN_TKN_ITER:
		iter->bs->plugin->ptn_tkn_iter_pos_free(iter, pos);
		break;
	case BTKN_HIST_ITER:
		iter->bs->plugin->tkn_hist_iter_pos_free(iter, pos);
		break;
	case BPTN_HIST_ITER:
		iter->bs->plugin->ptn_hist_iter_pos_free(iter, pos);
		break;
	case BCOMP_HIST_ITER:
		iter->bs->plugin->comp_hist_iter_pos_free(iter, pos);
		break;
	default:
		assert(0 == "Unknown iterator type");
		return;
	}
}

bstore_iter_pos_handle_t bstore_iter_pos_get(bstore_iter_t iter)
{
	/* NOTE:
	 *  - get an actual position object from the underlying iterator
	 *  - add the object into the hash table
	 *    - use hash key as position object handle for later use
	 */
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	struct timeval tv;
	int rc;
	bstore_iter_pos_handle_t handle = 0;
	bstore_iter_pos_t pos;
	struct pos_handle_entry *ent;
	pthread_mutex_lock(&mutex);
	switch (iter->type) {
	case BTKN_ITER:
		pos = iter->bs->plugin->tkn_iter_pos_get(iter);
		break;
	case BMSG_ITER:
		pos = iter->bs->plugin->msg_iter_pos_get(iter);
		break;
	case BPTN_ITER:
		pos = iter->bs->plugin->ptn_iter_pos_get(iter);
		break;
	case BPTN_TKN_ITER:
		pos = iter->bs->plugin->ptn_tkn_iter_pos_get(iter);
		break;
	case BTKN_HIST_ITER:
		pos = iter->bs->plugin->tkn_hist_iter_pos_get(iter);
		break;
	case BPTN_HIST_ITER:
		pos = iter->bs->plugin->ptn_hist_iter_pos_get(iter);
		break;
	case BCOMP_HIST_ITER:
		pos = iter->bs->plugin->comp_hist_iter_pos_get(iter);
		break;
	default:
		assert(0 == "Bad iterator type!!!");
		errno = EINVAL;
		goto out;
	}

	if (!pos) {
		goto out; /* errno is set by the plugin function call */
	}
	ent = calloc(1, sizeof(*ent));
	if (!ent) {
		__bstore_iter_pos_free(iter, pos);
		goto out;
	}
	ent->pos = pos;
	rbn_init(&ent->rbn, &ent->handle);
again:
	gettimeofday(&tv, 0);
	ent->handle = (tv.tv_sec<<20) | (tv.tv_usec & 0xFFFFF);
	rc = rbt_visit(iter->bs->pos_rbt, &ent->handle, __pos_get_cb, ent);
	if (!ent->handle)
		goto again;

	if (rc) {
		errno = rc;
		__bstore_iter_pos_free(iter, pos);
		free(ent);
	}
	handle = ent->handle;
out:
	pthread_mutex_unlock(&mutex);
	return handle;
}

rbt_visit_action_t __pos_put_cb(struct rbn *rbn, const void *key, void *cb_arg,
				struct rbn **new_rbn)
{
	struct pos_handle_entry **ent = cb_arg;
	bstore_iter_pos_handle_t handle = *(bstore_iter_pos_handle_t*)key;
	if (rbn) {
		/* found, delete it */
		*ent = container_of(rbn, struct pos_handle_entry, rbn);
		return RBT_VISIT_ACTION_DEL;
	}
	*ent = NULL;
	return RBT_VISIT_ACTION_NOOP;
}

void bstore_iter_pos_put(bstore_iter_t iter, bstore_iter_pos_handle_t pos_h)
{
	int rc;
	struct pos_handle_entry *ent;
	rc = rbt_visit(iter->bs->pos_rbt, &pos_h, __pos_put_cb, &ent);
	if (rc || !ent) {
		bwarn("Removing invalid position %ld", pos_h);
		return;
	}
	if (iter->type != ent->pos->type) {
		assert(0 == "Iterator - Position type mismatch");
		return;
	}
	__bstore_iter_pos_free(iter, ent->pos);
	free(ent);
}

int bstore_iter_pos_set(bstore_iter_t iter, bstore_iter_pos_handle_t pos_h)
{
	int rc;
	struct pos_handle_entry *ent;
	rc = rbt_visit(iter->bs->pos_rbt, &pos_h, __pos_put_cb, &ent);
	if (rc)
		return rc;
	if (!ent)
		return ENOENT;
	if (iter->type != ent->pos->type) {
		assert(0 == "Position-Iterator type mismatched");
		return EINVAL; /* type mismatch */
	}
	switch (iter->type) {
	case BTKN_ITER:
		rc = iter->bs->plugin->tkn_iter_pos_set(iter, ent->pos);
		break;
	case BMSG_ITER:
		rc = iter->bs->plugin->msg_iter_pos_set(iter, ent->pos);
		break;
	case BPTN_ITER:
		rc = iter->bs->plugin->ptn_iter_pos_set(iter, ent->pos);
		break;
	case BPTN_TKN_ITER:
		rc = iter->bs->plugin->ptn_tkn_iter_pos_set(iter, ent->pos);
		break;
	case BTKN_HIST_ITER:
		rc = iter->bs->plugin->tkn_hist_iter_pos_set(iter, ent->pos);
		break;
	case BPTN_HIST_ITER:
		rc = iter->bs->plugin->ptn_hist_iter_pos_set(iter, ent->pos);
		break;
	case BCOMP_HIST_ITER:
		rc = iter->bs->plugin->comp_hist_iter_pos_set(iter, ent->pos);
		break;
	default:
		assert(0 == "Bad iterator type!!!");
		rc = EINVAL;
	}
	free(ent);
	return rc;
}

char *bstore_pos_to_str(bstore_iter_pos_handle_t pos_h)
{
	int i;
	char *data = (void*)&pos_h;
	char *s;
	char *str = malloc(sizeof(pos_h) + 1); /* data_len + data + \0 */
	if (!str)
		return NULL;
	s = str;
	for (i = 0; i < sizeof(pos_h); i++) {
		s += sprintf(s, "%02hhX", data[i]);
	}
	return str;
}

bstore_iter_pos_handle_t bstore_pos_from_str(const char *str)
{
	int i;
	bstore_iter_pos_handle_t pos_h;
	char *data = (void*)&pos_h;
	for (i = 0; i < sizeof(pos_h); i++) {
		sscanf(str+2*i, "%02hhX", &data[i]);
	}
	return pos_h;
}

static void __attribute__ ((destructor)) bstore_term(void)
{
	struct plugin_entry *pe;
	struct rbn *rbn;
	for (rbn = rbt_min(&plugin_tree); rbn; rbn = rbt_min(&plugin_tree)) {
		rbt_del(&plugin_tree, rbn);
		pe = container_of(rbn, struct plugin_entry, rbn);
		free(pe);
	}
}
