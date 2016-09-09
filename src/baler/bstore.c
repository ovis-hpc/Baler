#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <limits.h>
#include <coll/rbt.h>
#include <bstore.h>
#include <butils.h>
#include <stdarg.h>
#include <pthread.h>

struct plugin_entry {
	bstore_plugin_t plugin;
	struct rbn rbn;
};

pthread_mutex_t plugin_lock;
static int plugin_cmp(void *a, const void *b)
{
	return strcmp(a, b);
}

struct rbt plugin_tree = RBT_INITIALIZER(plugin_cmp);

static bstore_plugin_t get_plugin(const char *name)
{
	struct plugin_entry *pe;
	char *plugin_path;
	char *plugin_dir;
	bstore_plugin_t plugin;
	struct rbn *rbn;
	void *dl;
	bstore_init_fn_t init_store;

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
	init_store = dlsym(dl, "init_store");
	if (!init_store)
		goto err_2;
	pe = malloc(sizeof *pe);
	if (!pe)
		goto err_2;
	plugin = init_store();
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

bstore_t bstore_open(const char *name, const char *path, int flags, ...)
{
	bstore_t store = NULL;
	va_list ap;
	int o_mode;
	bstore_plugin_t plugin = get_plugin(name);
	if (!plugin)
		return NULL;
	va_start(ap, flags);
	o_mode = va_arg(ap, int);
	store = plugin->open(plugin, path, flags, o_mode);
 err_0:
	return store;
}

void bstore_close(bstore_t bs)
{
	bs->plugin->close(bs);
}

btkn_id_t bstore_tkn_add(bstore_t bs, btkn_t tkn)
{
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
	return bs->plugin->tkn_find_by_name(bs, text, text_len);
}

bstore_iter_pos_t bstore_tkn_iter_pos(btkn_iter_t iter)
{
	return iter->bs->plugin->tkn_iter_pos(iter);
}

int bstore_tkn_iter_pos_set(btkn_iter_t iter, bstore_iter_pos_t pos)
{
	return iter->bs->plugin->tkn_iter_pos_set(iter, pos);
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

btkn_t bstore_tkn_iter_first(btkn_iter_t iter)
{
	return iter->bs->plugin->tkn_iter_first(iter);
}

btkn_t bstore_tkn_iter_obj(btkn_iter_t iter)
{
	return iter->bs->plugin->tkn_iter_obj(iter);
}

btkn_t bstore_tkn_iter_next(btkn_iter_t iter)
{
	return iter->bs->plugin->tkn_iter_next(iter);
}

bstore_iter_pos_t bstore_ptn_iter_pos(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_pos(iter);
}

int bstore_ptn_iter_pos_set(bptn_iter_t iter, bstore_iter_pos_t pos)
{
	return iter->bs->plugin->ptn_iter_pos_set(iter, pos);
}

bptn_iter_t bstore_ptn_iter_new(bstore_t bs)
{
	return bs->plugin->ptn_iter_new(bs);
}

void bstore_ptn_iter_free(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_free(iter);
}

uint64_t bstore_ptn_iter_card(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_card(iter);
}

bptn_t bstore_ptn_iter_find(bptn_iter_t iter, time_t start)
{
	return iter->bs->plugin->ptn_iter_find(iter, start);
}

bptn_t bstore_ptn_iter_obj(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_obj(iter);
}

bptn_t bstore_ptn_iter_next(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_next(iter);
}

bptn_t bstore_ptn_iter_prev(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_prev(iter);
}

bptn_t bstore_ptn_iter_first(bptn_iter_t iter)
{
	return iter->bs->plugin->ptn_iter_first(iter);
}

bptn_t bstore_ptn_iter_last(bptn_iter_t iter)
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

int bstore_msg_add(bstore_t bs, struct timeval *tv, bmsg_t msg)
{
	return bs->plugin->msg_add(bs, tv, msg);
}

bstore_iter_pos_t bstore_msg_iter_pos(bmsg_iter_t iter)
{
	return iter->bs->plugin->msg_iter_pos(iter);
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
bmsg_t bstore_msg_iter_find(bmsg_iter_t iter,
			    time_t start, bptn_id_t ptn_id, bcomp_id_t comp_id,
			    bmsg_cmp_fn_t cmp_fn, void *ctxt)
{
	return iter->bs->plugin->msg_iter_find(iter, start, ptn_id, comp_id, cmp_fn, ctxt);
}

int bstore_msg_iter_pos_set(bmsg_iter_t iter, bstore_iter_pos_t pos)
{
	return iter->bs->plugin->msg_iter_pos_set(iter, pos);
}

bmsg_t bstore_msg_iter_obj(bmsg_iter_t iter)
{
	return iter->bs->plugin->msg_iter_obj(iter);
}

bmsg_t bstore_msg_iter_next(bmsg_iter_t iter)
{
	return iter->bs->plugin->msg_iter_next(iter);
}

bmsg_t bstore_msg_iter_prev(bmsg_iter_t iter)
{
	return iter->bs->plugin->msg_iter_prev(iter);
}

bmsg_t bstore_msg_iter_first(bmsg_iter_t iter)
{
	return iter->bs->plugin->msg_iter_first(iter);
}

bmsg_t bstore_msg_iter_last(bmsg_iter_t iter)
{
	return iter->bs->plugin->msg_iter_last(iter);
}

bstore_iter_pos_t bstore_ptn_tkn_iter_pos(bptn_tkn_iter_t iter)
{
	return iter->bs->plugin->ptn_tkn_iter_pos(iter);
}

int bstore_ptn_tkn_iter_pos_set(bptn_tkn_iter_t iter, bstore_iter_pos_t pos)
{
	return iter->bs->plugin->ptn_tkn_iter_pos_set(iter, pos);
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

btkn_t bstore_ptn_tkn_iter_find(bptn_tkn_iter_t iter, bptn_id_t ptn_id, uint64_t pos)
{
	return iter->bs->plugin->ptn_tkn_iter_find(iter, ptn_id, pos);
}

btkn_t bstore_ptn_tkn_iter_obj(bptn_tkn_iter_t iter)
{
	return iter->bs->plugin->ptn_tkn_iter_obj(iter);
}

btkn_t bstore_ptn_tkn_iter_next(bptn_tkn_iter_t iter)
{
	return iter->bs->plugin->ptn_tkn_iter_next(iter);
}

btkn_type_t bstore_tkn_type_get(bstore_t bs, const char *name, size_t len)
{
	return bs->plugin->tkn_type_get(bs, name, len);
}

int bstore_tkn_hist_update(bstore_t bs, time_t sec, time_t bin_width, btkn_id_t tkn_id)
{
	return bs->plugin->tkn_hist_update(bs, sec, bin_width, tkn_id);
}

bstore_iter_pos_t bstore_tkn_hist_iter_pos(btkn_hist_iter_t iter)
{
	return iter->bs->plugin->tkn_hist_iter_pos(iter);
}

int bstore_tkn_hist_iter_pos_set(btkn_hist_iter_t iter, bstore_iter_pos_t pos)
{
	return iter->bs->plugin->tkn_hist_iter_pos_set(iter, pos);
}

btkn_hist_iter_t bstore_tkn_hist_iter_new(bstore_t bs)
{
	return bs->plugin->tkn_hist_iter_new(bs);
}

void bstore_tkn_hist_iter_free(btkn_hist_iter_t i)
{
	i->bs->plugin->tkn_hist_iter_free(i);
}

btkn_hist_t bstore_tkn_hist_iter_find(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	return iter->bs->plugin->tkn_hist_iter_find(iter, tkn_h);
}

btkn_hist_t bstore_tkn_hist_iter_obj(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	return iter->bs->plugin->tkn_hist_iter_obj(iter, tkn_h);
}

btkn_hist_t bstore_tkn_hist_iter_next(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	return iter->bs->plugin->tkn_hist_iter_next(iter, tkn_h);
}

btkn_hist_t bstore_tkn_hist_iter_first(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	return iter->bs->plugin->tkn_hist_iter_first(iter, tkn_h);
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

bstore_iter_pos_t bstore_ptn_hist_iter_pos(bptn_hist_iter_t iter)
{
	return iter->bs->plugin->ptn_hist_iter_pos(iter);
}

int bstore_ptn_hist_iter_pos_set(bptn_hist_iter_t iter, bstore_iter_pos_t pos)
{
	return iter->bs->plugin->ptn_hist_iter_pos_set(iter, pos);
}

bptn_hist_iter_t bstore_ptn_hist_iter_new(bstore_t bs)
{
	return bs->plugin->ptn_hist_iter_new(bs);
}

void bstore_ptn_hist_iter_free(bptn_hist_iter_t i)
{
	i->bs->plugin->ptn_hist_iter_free(i);
}

bptn_hist_t bstore_ptn_hist_iter_find(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	return iter->bs->plugin->ptn_hist_iter_find(iter, ptn_h);
}

bptn_hist_t bstore_ptn_hist_iter_obj(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	return iter->bs->plugin->ptn_hist_iter_obj(iter, ptn_h);
}

bptn_hist_t bstore_ptn_hist_iter_next(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	return iter->bs->plugin->ptn_hist_iter_next(iter, ptn_h);
}

bptn_hist_t bstore_ptn_hist_iter_first(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	return iter->bs->plugin->ptn_hist_iter_first(iter, ptn_h);
}

bstore_iter_pos_t bstore_comp_hist_iter_pos(bcomp_hist_iter_t iter)
{
	return iter->bs->plugin->comp_hist_iter_pos(iter);
}

int bstore_comp_hist_iter_pos_set(bcomp_hist_iter_t iter, bstore_iter_pos_t pos)
{
	return iter->bs->plugin->comp_hist_iter_pos_set(iter, pos);
}

bcomp_hist_iter_t bstore_comp_hist_iter_new(bstore_t bs)
{
	return bs->plugin->comp_hist_iter_new(bs);
}

void bstore_comp_hist_iter_free(bcomp_hist_iter_t i)
{
	i->bs->plugin->comp_hist_iter_free(i);
}

bcomp_hist_t bstore_comp_hist_iter_find(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	return iter->bs->plugin->comp_hist_iter_find(iter, comp_h);
}

bcomp_hist_t bstore_comp_hist_iter_obj(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	return iter->bs->plugin->comp_hist_iter_obj(iter, comp_h);
}

bcomp_hist_t bstore_comp_hist_iter_next(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	return iter->bs->plugin->comp_hist_iter_next(iter, comp_h);
}

bcomp_hist_t bstore_comp_hist_iter_first(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	return iter->bs->plugin->comp_hist_iter_first(iter, comp_h);
}

const char *bstore_iter_pos_to_str(bstore_iter_t iter, bstore_iter_pos_t pos)
{
	return iter->bs->plugin->iter_pos_to_str(iter, pos);
}

bstore_iter_pos_t bstore_iter_pos_from_str(bstore_iter_t iter, const char *pos)
{
	return iter->bs->plugin->iter_pos_from_str(iter, pos);
}

void bstore_iter_pos_free(bstore_iter_t iter, bstore_iter_pos_t pos)
{
	return iter->bs->plugin->iter_pos_free(iter, pos);
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
