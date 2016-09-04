#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>
#include <assert.h>
#include <endian.h>
#include <sos/sos.h>
#include "baler/btypes.h"
#include "baler/bhash.h"
#include "baler/btkn.h"
#include "baler/bptn.h"
#include "baler/bhash.h"
#include "baler/bstore.h"
#include "bsos_msg.h"

typedef struct bstore_htbl_s {
	struct bstore_s base;

	struct btkn_store *tkn_store; /**< Token store */
	struct bptn_store *ptn_store; /**< Pattern store */
	struct btkn_store *comp_store; /**< Token store for comp_id */
	struct bsos_msg *sos_msg;
	pthread_mutex_t sos_mutex;
} *bstore_htbl_t;

static int bs_tkn_add_with_id(bstore_t bs, btkn_t tkn);

#define BSOS_MSG_IDX_PTH_NAME "index_pth"
#define BSOS_MSG_IDX_TH_NAME "index_th"

static void verify_ptn(const struct bstr *ptn)
{
	int arg;
	int tkn_count = ptn->blen / sizeof(uint64_t);
	assert(0 == (ptn->blen % sizeof(uint64_t)));
	for (arg = 0; arg < tkn_count; arg++) {
		btkn_id_t tkn_id;
		btkn_type_t tkn_type;
		uint64_t u64 = ptn->u64str[arg];
		tkn_id = u64 >> 8;
		tkn_type = u64 & 0xff;
		assert((tkn_id & 0xFF000000) == 0);
		assert(tkn_type < 20);
	}
}

static sos_t __sos_container_open(const char *path, int create)
{
	int rc;
	sos_t sos;
	sos_part_t part;
	char buff[16];
	struct timeval tv;
retry:
	sos = sos_container_open(path, SOS_PERM_RW);
	if (!sos && create) {
		rc = sos_container_new(path, 0660);
		if (rc)
			goto err0;
		sos = sos_container_open(path, SOS_PERM_RW);
		if (!sos)
			goto err0;
		/* Create/set active partition */
		time_t t = time(NULL);
		snprintf(buff, sizeof(buff), "%d", t);
		rc = sos_part_create(sos, buff, NULL);
		if (rc)
			goto err1;
		part = sos_part_find(sos, buff);
		assert(part);
		rc = sos_part_state_set(part, SOS_PART_STATE_PRIMARY);
		sos_part_put(part);
	}
	return sos;
	/* TODO cleanup partially created container */
err1:
	sos_container_close(sos, SOS_COMMIT_ASYNC);
err0:
	return NULL;
}

static
sos_index_t __sos_index_open(sos_t sos, int create, const char *name, const char *index,
				const char *type,
				const char *opt)
{
	int rc;
	sos_index_t idx = NULL;
retry:
	idx = sos_index_open(sos, name);
	if (!idx && create) {
		rc = sos_index_new(sos, name, index, type, opt);
		if (!rc)
			goto retry;
		goto out;
	}
out:
	return idx;
}

bsos_msg_t bsos_msg_open(const char *path, int create)
{
	int rc;
	bsos_msg_t bsos_msg = calloc(1, sizeof(*bsos_msg));
	if (!bsos_msg)
		goto out;
	bsos_msg->sos = __sos_container_open(path, create);
	if (!bsos_msg->sos)
		goto err;

	bsos_msg->index_ptc = __sos_index_open(bsos_msg->sos, create,
			BSOS_MSG_IDX_PTH_NAME, "BXTREE", "UINT96", "ORDER=5");
	if (!bsos_msg->index_ptc)
		goto err;
	bsos_msg->index_tc = __sos_index_open(bsos_msg->sos, create,
			BSOS_MSG_IDX_TH_NAME, "BXTREE", "UINT64", "ORDER=5");
	if (!bsos_msg->index_tc)
		goto err;

	return bsos_msg;

err:
	bsos_msg_close(bsos_msg, SOS_COMMIT_ASYNC);
out:
	return NULL;
}

void bsos_msg_close(bsos_msg_t bsos_msg, sos_commit_t commit)
{
	if (bsos_msg->index_ptc)
		sos_index_close(bsos_msg->index_ptc, commit);
	if (bsos_msg->index_tc)
		sos_index_close(bsos_msg->index_tc, commit);
	if (bsos_msg->sos)
		sos_container_close(bsos_msg->sos, commit);
	free(bsos_msg);
}

static bstore_t bs_open(bstore_plugin_t plugin, const char *store_path,
			int flags, int o_mode)
{
	char tmp[PATH_MAX];
	bstore_htbl_t hs = malloc(sizeof *hs);
	if (!hs)
		return NULL;

	hs->base.plugin = plugin;
	hs->base.path = strdup(store_path);
	if (!hs->base.path)
		goto err_1;

	/* Message Store */
	hs->sos_msg = bsos_msg_open(store_path, flags & O_CREAT);
	if (!hs->sos_msg)
		goto err_2;
	pthread_mutex_init(&hs->sos_mutex, NULL);

	/* Token/Pattern stores */
	sprintf(tmp, "%s/tkn_store", store_path);
	hs->tkn_store = btkn_store_open(tmp, flags);
	if (!hs->tkn_store) {
		berror("btkn_store_open");
		berr("Cannot open token store: %s", tmp);
		goto err_2;
	}

	/* Add the spaces into the store */
	btkn_store_char_insert(hs->tkn_store, " \t\r\n", BTKN_TYPE_WHITESPACE);
	btkn_store_char_insert(hs->tkn_store, BTKN_SYMBOL_STR, BTKN_TYPE_SEPARATOR);

	sprintf(tmp, "%s/ptn_store", store_path);
	hs->ptn_store = bptn_store_open(tmp, flags);
	if (!hs->ptn_store) {
		berror("bptn_store_open");
		berr("Cannot open pattern store: %s", tmp);
		goto err_2;
	}

	/* Comp store for comp<->comp_id */
	sprintf(tmp, "%s/comp_store", store_path);
	hs->comp_store = btkn_store_open(tmp, flags);
	if (!hs->comp_store) {
		berror("btkn_store_open");
		berr("Cannot open token store: %s", tmp);
		goto err_2;
	}

	if (0 == (flags & O_CREAT))
		goto out;
	btkn_type_t type;
	for (type = BTKN_TYPE_FIRST+1; type < BTKN_TYPE_LAST; type++) {
		char type_name[80];
		btkn_t tkn;
		btkn_id_t tkn_id;
		sprintf(type_name, "_%s_", btkn_attr_type_str(type));
		tkn = btkn_alloc(type, BTKN_TYPE_MASK(type), type_name, strlen(type_name));
		tkn->tkn_type_mask |= BTKN_TYPE_MASK(BTKN_TYPE_TYPE);
		int rc = bs_tkn_add_with_id(&hs->base, tkn);
		assert(0 == rc);
		btkn_free(tkn);
	}
 out:
	return &hs->base;
 err_2:
	free(hs->base.path);
 err_1:
	free(hs);
	errno = EPERM;
	return NULL;
}

static void bs_close(bstore_t bs)
{
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	if (hs) {
		if (hs->sos_msg)
			bsos_msg_close(hs->sos_msg, SOS_COMMIT_SYNC);
		free(hs);
	}
}

static btkn_id_t bs_tkn_add(bstore_t bs, btkn_t tkn)
{
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	btkn_id_t tkn_id = btkn_store_insert(hs->tkn_store, tkn->tkn_str);
	if (tkn_id == BMAP_ID_ERR) {
		berr("cannot insert '%s' into token store", tkn->tkn_str->cstr);
		return 0;
	}
	struct btkn_attr attr = btkn_store_get_attr(hs->tkn_store, tkn_id);
	attr.type |= tkn->tkn_type_mask;
	btkn_store_set_attr(hs->tkn_store, tkn_id, attr);
	tkn->tkn_type_mask = attr.type;
	return tkn_id;
}

static int bs_tkn_add_with_id(bstore_t bs, btkn_t tkn)
{
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	int rc = 0;
	uint32_t tkn_id;
	bmap_ins_ret_t ret_flag;
	tkn_id = bmap_insert_with_id(hs->tkn_store->map, tkn->tkn_str, tkn->tkn_id);
	if (!tkn_id) {
		/* errno should be set in bmap_insert() */
		rc = errno;
		goto out;
	}
	struct btkn_attr attr = btkn_store_get_attr(hs->tkn_store, tkn_id);
	attr.type |= tkn->tkn_type_mask;
	btkn_store_set_attr(hs->tkn_store, tkn_id, attr);
	tkn->tkn_type_mask = attr.type;
out:
	return rc;
}

static btkn_t __make_tkn(bstore_htbl_t hs, btkn_id_t tkn_id, const struct bstr *tkn_str)
{
	btkn_t tkn;
	const struct bstr *bstr;
	struct btkn_attr attr = btkn_store_get_attr(hs->tkn_store, tkn_id);
	tkn = btkn_alloc(tkn_id, attr.type, tkn_str->cstr, tkn_str->blen);
	return tkn;
}

static btkn_t bs_tkn_find_by_id(bstore_t bs, btkn_id_t tkn_id)
{
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	const struct bstr *tkn_str = btkn_store_get_bstr(hs->tkn_store, (uint32_t)tkn_id);
	if (!tkn_str)
		return NULL;
	return __make_tkn(hs, tkn_id, tkn_str);
}

static btkn_t bs_tkn_find_by_name(bstore_t bs,
				  const char *text, size_t text_len)
{
	btkn_t tkn;
	btkn_id_t tkn_id;
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	struct bstr *tkn_str = bstr_alloc_init_cstr(text);
	if (!tkn_str) {
		errno = ENOMEM;
		return NULL;
	}
	tkn_id = btkn_store_get_id(hs->tkn_store, tkn_str);
	if (!tkn_id)
		goto enoent;

	tkn = __make_tkn(hs, tkn_id, tkn_str);
	bstr_free(tkn_str);
	return tkn;
 enoent:
	bstr_free(tkn_str);
	errno = ENOENT;
	return NULL;
}

typedef struct bhtbl_iter_s {
#if 0
	union {
		struct btkn_iter_s ti;
		struct bmsg_iter_s mi;
		struct bptn_iter_s pi;
		struct bptn_tkn_iter_s pti;
	};
#endif
	struct bstore_iter_s base;
	btkn_id_t tkn_id;
	bptn_id_t ptn_id;
	bcomp_id_t comp_id;
	time_t start;

	sos_iter_t sos_iter;
	struct bptn_attrM *attrM;
	struct bmlnode_u32 *ptn_tkn_elm;
} *bhtbl_iter_t;

static btkn_iter_t bs_tkn_iter_new(bstore_t bs)
{
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	bhtbl_iter_t ti = malloc(sizeof(*ti));
	if (ti) {
		ti->base.bs = bs;
	}
	return &ti->base;
}

static void bs_tkn_iter_free(btkn_iter_t i)
{
	free(i);
}

static uint64_t __tkn_last_id(bstore_htbl_t hs)
{
	return hs->tkn_store->map->hdr->next_id - 1;
}

static uint64_t __tkn_first_id(bstore_htbl_t hs)
{
	return 1;
}

static uint64_t bs_tkn_iter_card(btkn_iter_t i)
{
	bstore_htbl_t hs = (bstore_htbl_t)i->bs;
	return __tkn_last_id(hs) - __tkn_first_id(hs);
}

static btkn_id_t __next_tkn_id(bstore_htbl_t hs, btkn_id_t id, const struct bstr **pstr)
{
	const struct bstr *tkn_str;
	btkn_id_t last_id = __tkn_last_id(hs);
	for (; id <= last_id; id++) {
		tkn_str = bmap_get_bstr(hs->tkn_store->map, id);
		if (tkn_str) {
			*pstr = tkn_str;
			return id;
		}
	}
	return 0;
}

static btkn_t bs_tkn_iter_first(btkn_iter_t iter)
{
	bstore_htbl_t hs = (bstore_htbl_t)iter->bs;
	bhtbl_iter_t i = (bhtbl_iter_t)iter;
	const struct bstr *tkn_str;
	btkn_id_t tkn_id = __next_tkn_id(hs, __tkn_first_id(hs), &tkn_str);
	if (!tkn_id)
		return NULL;
	i->tkn_id = tkn_id;
	return __make_tkn(hs, tkn_id, tkn_str);
}

static btkn_t bs_tkn_iter_next(btkn_iter_t iter)
{
	bhtbl_iter_t i = (bhtbl_iter_t)iter;
	bstore_htbl_t hs = (bstore_htbl_t)i->base.bs;
	const struct bstr *tkn_str;
	btkn_id_t tkn_id = __next_tkn_id(hs, i->tkn_id+1, &tkn_str);
	if (!tkn_id)
		return NULL;
	i->tkn_id = tkn_id;
	return __make_tkn(hs, tkn_id, tkn_str);
}

static bptn_iter_t bs_ptn_iter_new(bstore_t bs)
{
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	bhtbl_iter_t pi = malloc(sizeof(*pi));
	if (pi) {
		pi->base.bs = bs;
	}
	return &pi->base;
}
static void bs_ptn_iter_free(bptn_iter_t i)
{
	free(i);
}

static uint64_t bs_ptn_iter_card(bptn_iter_t i)
{
	bstore_htbl_t hs = (bstore_htbl_t)i->bs;
	return bptn_store_last_id(hs->ptn_store) - bptn_store_first_id(hs->ptn_store);
}

static bptn_t __make_ptn(bstore_htbl_t hs, bptn_id_t ptn_id, const struct bstr *ptn_str)
{
	bptn_t ptn;
	size_t tkn_count = ptn_str->blen / sizeof(ptn_str->u64str[0]);
	uint64_t attrM_off = bmvec_u64_get(hs->ptn_store->attr_idx, ptn_id);
	struct bptn_attrM *attrM = BMPTR(hs->ptn_store->mattr, attrM_off);

	verify_ptn(ptn_str);
	ptn = bptn_alloc(tkn_count);
	if (!ptn)
		return NULL;

	ptn->ptn_id = ptn_id;
	ptn->first_seen = attrM->first_seen;
	ptn->last_seen = attrM->last_seen;
	ptn->count = attrM->count;
	ptn->tkn_count = tkn_count;
	memcpy(ptn->str, ptn_str, sizeof(*ptn_str) + ptn_str->blen);

	return ptn;
}

static bptn_t bs_ptn_find(bstore_t bs, bptn_id_t ptn_id)
{
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	const struct bstr *ptn_str = bmap_get_bstr(hs->ptn_store->map, ptn_id);
	if (!ptn_str)
		return NULL;

	return __make_ptn(hs, ptn_id, ptn_str);
}

static bptn_id_t __next_ptn_id(bstore_htbl_t hs, bptn_id_t id, const struct bstr **pstr)
{
	const struct bstr *ptn_str;
	bptn_id_t last_id = bptn_store_last_id(hs->ptn_store);
	for (; id <= last_id; id++) {
		ptn_str = bmap_get_bstr(hs->ptn_store->map, id);
		if (ptn_str) {
			*pstr = ptn_str;
			return id;
		}
	}
	return 0;
}

static bptn_id_t __prev_ptn_id(bstore_htbl_t hs, bptn_id_t id, const struct bstr **pstr)
{
	const struct bstr *ptn_str;
	bptn_id_t first_id = bptn_store_first_id(hs->ptn_store);
	for (; id >= first_id; id--) {
		ptn_str = bmap_get_bstr(hs->ptn_store->map, id);
		if (ptn_str) {
			*pstr = ptn_str;
			return id;
		}
	}
	return 0;
}

static bptn_t bs_ptn_iter_first(bptn_iter_t iter)
{
	bhtbl_iter_t i = (bhtbl_iter_t)iter;
	bstore_htbl_t hs = (bstore_htbl_t)i->base.bs;
	const struct bstr *ptn_str;
	bptn_id_t id = __next_ptn_id(hs, bptn_store_first_id(hs->ptn_store), &ptn_str);
	if (!id)
		return NULL;
	i->ptn_id = id;
	return __make_ptn(hs, id, ptn_str);
}

static bptn_t bs_ptn_iter_find(bptn_iter_t iter, time_t start)
{
	return bs_ptn_iter_first(iter);
}

static bptn_t bs_ptn_iter_last(bptn_iter_t iter)
{
	bhtbl_iter_t i = (bhtbl_iter_t)iter;
	bstore_htbl_t hs = (bstore_htbl_t)i->base.bs;
	const struct bstr *ptn_str;
	bptn_id_t id = __prev_ptn_id(hs, bptn_store_last_id(hs->ptn_store), &ptn_str);
	if (!id)
		return NULL;
	i->ptn_id = id;
	return __make_ptn(hs, id, ptn_str);
}

static bptn_t bs_ptn_iter_next(bptn_iter_t iter)
{
	bhtbl_iter_t i = (bhtbl_iter_t)iter;
	bstore_htbl_t hs = (bstore_htbl_t)i->base.bs;
	const struct bstr *ptn_str;
	bptn_id_t ptn_id = __next_ptn_id(hs, i->ptn_id+1, &ptn_str);
	if (!ptn_id)
		return NULL;
	i->ptn_id = ptn_id;
	return __make_ptn(hs, ptn_id, ptn_str);
}

static bptn_t bs_ptn_iter_prev(bptn_iter_t iter)
{
	bhtbl_iter_t i = (bhtbl_iter_t)iter;
	bstore_htbl_t hs = (bstore_htbl_t)i->base.bs;
	const struct bstr *ptn_str;
	bptn_id_t ptn_id = __prev_ptn_id(hs, i->ptn_id-1, &ptn_str);
	if (!ptn_id)
		return NULL;
	i->ptn_id = ptn_id;
	return __make_ptn(hs, ptn_id, ptn_str);
}

static bptn_tkn_iter_t bs_ptn_tkn_iter_new(bstore_t bs)
{
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	bhtbl_iter_t pti = malloc(sizeof(*pti));
	if (pti) {
		pti->base.bs = bs;
	}
	return &pti->base;
}
static void bs_ptn_tkn_iter_free(bptn_tkn_iter_t i)
{
	free(i);
}

static uint64_t bs_ptn_tkn_iter_card(bptn_tkn_iter_t i)
{
	return 0;
}

static bmsg_iter_t bs_msg_iter_new(bstore_t bs)
{
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	bhtbl_iter_t mi = calloc(1, sizeof(*mi));
	if (mi)
		mi->base.bs = bs;
	return &mi->base;
}

static void bs_msg_iter_free(bmsg_iter_t i)
{
	bhtbl_iter_t hi = (bhtbl_iter_t)i;
	if (hi->sos_iter)
		sos_iter_free(hi->sos_iter);
	free(hi);
}

static uint64_t bs_msg_iter_card(bmsg_iter_t i)
{
	bhtbl_iter_t hi = (bhtbl_iter_t)i;
	return sos_iter_card(hi->sos_iter);
}

static bmsg_t __make_msg(bstore_htbl_t hs, sos_obj_t obj)
{
	bmsg_t bmsg = NULL;
	sos_array_t msg = sos_obj_ptr(obj);
	int arg, argc = msg->count - BSOS_MSG_ARGV_0;
	bmsg = bmsg_alloc(argc);
	if (!bmsg)
		goto err;
	bmsg->argc = argc;
	bmsg->ptn_id = (uint64_t)msg->data.uint32_[BSOS_MSG_PTN_ID];
	bmsg->comp_id = (uint64_t)msg->data.uint32_[BSOS_MSG_COMP_ID];
	bmsg->timestamp.tv_sec = (uint64_t)msg->data.uint32_[BSOS_MSG_SEC];
	bmsg->timestamp.tv_usec = (uint64_t)msg->data.uint32_[BSOS_MSG_USEC];
	for (arg = 0; arg < argc; arg++)
		bmsg->argv[arg] = msg->data.uint32_[arg + BSOS_MSG_ARGV_0];
 err:
	sos_obj_put(obj);
	return bmsg;
}

static sos_obj_t __next_matching_msg(int rc, bhtbl_iter_t hi, int forwards)
{
	sos_array_t msg;
	bptn_id_t msg_ptn;
	time_t msg_time;
	bcomp_id_t msg_comp;
	sos_obj_t obj;

	for (; 0 == rc; rc = (forwards?sos_iter_next(hi->sos_iter):sos_iter_prev(hi->sos_iter))) {
		obj = sos_iter_obj(hi->sos_iter);
		msg = sos_obj_ptr(obj);
		msg_ptn = (uint64_t)msg->data.uint32_[BSOS_MSG_PTN_ID];
		msg_comp = (uint64_t)msg->data.uint32_[BSOS_MSG_COMP_ID];
		msg_time = msg->data.uint32_[BSOS_MSG_SEC];

		/* ptn_id specified and doesn't match, exit */
		if (hi->ptn_id) {
			/* We're using the pt_msg_key index */
			if (hi->ptn_id != msg_ptn)
				goto enoent;
			/* Skip component id's that don't match */
			if (hi->comp_id && (hi->comp_id != msg_comp)) {
				sos_obj_put(obj);
				continue;
			}
		}
		break;
	}
	if (!rc)
		return obj;
	return NULL;
 enoent:
	sos_obj_put(obj);
	return NULL;
}

static bmsg_t
bs_msg_iter_find(bmsg_iter_t iter,
		 time_t start, bptn_id_t ptn_id, bcomp_id_t comp_id,
		 bmsg_cmp_fn_t cmp_fn, void *ctxt)
{
	bhtbl_iter_t hi = (bhtbl_iter_t)iter;
	bstore_htbl_t hs = (bstore_htbl_t)iter->bs;
	SOS_KEY(key);
	ods_key_value_t kv = key->as.ptr;
	struct bsos_msg_key_ptc *ptc_k = (struct bsos_msg_key_ptc *)kv->value;
	struct bsos_msg_key_tc *tc_k = (struct bsos_msg_key_tc *)kv->value;

	/*
	 * If this iterator is being reused, release the previously
	 * allocated iterator
	 */
	if (hi->sos_iter)
		sos_iter_free(hi->sos_iter);
	/*
	 * If ptn_id is specified, use the ptc index, otherwise, use
	 * the tc index.
	 */
	if (ptn_id) {
		hi->sos_iter = sos_index_iter_new(hs->sos_msg->index_ptc);
		ptc_k->ptn_id = htobe32((uint32_t)ptn_id);
		ptc_k->sec = htobe32((uint32_t)start);
		ptc_k->comp_id = htobe32((uint32_t)comp_id);
		kv->len = 24;
	} else {
		hi->sos_iter = sos_index_iter_new(hs->sos_msg->index_tc);
		tc_k->sec = (uint32_t)start;
		tc_k->comp_id = (uint32_t)comp_id;
		kv->len = 8;
	}
	if (!hi->sos_iter) {
		errno = ENOMEM;
		return NULL;
	}
	hi->ptn_id = ptn_id;
	hi->comp_id = comp_id;
	hi->start = start;
	int rc = sos_iter_sup(hi->sos_iter, key);
	if (rc)
		return NULL;

	sos_obj_t obj = __next_matching_msg(rc, hi, 1);
	if (obj)
		return __make_msg(hs, obj);
	return NULL;
}

static bmsg_t
bs_msg_iter_first(bmsg_iter_t iter)
{
	bhtbl_iter_t hi = (bhtbl_iter_t)iter;
	bstore_htbl_t hs = (bstore_htbl_t)iter->bs;
	/*
	 * If this iterator is being reused, release the previously
	 * allocated iterator
	 */
	if (hi->sos_iter)
		sos_iter_free(hi->sos_iter);

	hi->sos_iter = sos_index_iter_new(hs->sos_msg->index_tc);
	if (!hi->sos_iter) {
		errno = ENOMEM;
		return NULL;
	}

	int rc = sos_iter_begin(hi->sos_iter);
	if (rc)
		return NULL;

	return __make_msg(hs, sos_iter_obj(hi->sos_iter));
}

static bmsg_t
bs_msg_iter_last(bmsg_iter_t iter)
{
	bhtbl_iter_t hi = (bhtbl_iter_t)iter;
	bstore_htbl_t hs = (bstore_htbl_t)iter->bs;
	/*
	 * If this iterator is being reused, release the previously
	 * allocated iterator
	 */
	if (hi->sos_iter)
		sos_iter_free(hi->sos_iter);

	hi->sos_iter = sos_index_iter_new(hs->sos_msg->index_tc);
	if (!hi->sos_iter) {
		errno = ENOMEM;
		return NULL;
	}

	int rc = sos_iter_end(hi->sos_iter);
	if (rc)
		return NULL;

	return __make_msg(hs, sos_iter_obj(hi->sos_iter));
}

static bmsg_t bs_msg_iter_next(bmsg_iter_t iter)
{
	bhtbl_iter_t hi = (bhtbl_iter_t)iter;
	bstore_htbl_t hs = (bstore_htbl_t)iter->bs;

	int rc = sos_iter_next(hi->sos_iter);
	if (rc)
		return NULL;

	sos_obj_t obj = __next_matching_msg(rc, hi, 1);
	if (obj)
		return __make_msg(hs, obj);
	return NULL;
}

static bmsg_t bs_msg_iter_prev(bmsg_iter_t iter)
{
	bhtbl_iter_t hi = (bhtbl_iter_t)iter;
	bstore_htbl_t hs = (bstore_htbl_t)iter->bs;

	int rc = sos_iter_prev(hi->sos_iter);
	if (rc)
		return NULL;

	sos_obj_t obj = __next_matching_msg(rc, hi, 0);
	if (obj)
		return __make_msg(hs, obj);
	return NULL;
}

static bptn_id_t bs_ptn_add(bstore_t bs, struct timeval *tv, bstr_t ptn)
{
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	uint32_t ptn_id;
	size_t tkn_count = ptn->blen / sizeof(ptn->u64str[0]);
	struct bptn_attr *attr;
	uint64_t attrM_off;
	struct bptn_attrM *attrM;

	verify_ptn(ptn);
	ptn_id = bptn_store_addptn(hs->ptn_store, ptn);
	if (!ptn_id)
		return 0;

	pthread_mutex_lock(&hs->ptn_store->mutex);
	attr = NULL;
	(void)barray_get(hs->ptn_store->aattr, ptn_id, &attr);
	if (!attr) {
		attr = bptn_attr_alloc(tkn_count);
		if (!attr)
			goto err_0;

		if (barray_set(hs->ptn_store->aattr, ptn_id, &attr))
			goto err_1;

		attrM_off = bmem_alloc(hs->ptn_store->mattr, sizeof(*attrM) +
				tkn_count * sizeof(typeof(attrM->arg_off[0])));
		if (!attrM_off)
			goto err_2;

		attrM = BMPTR(hs->ptn_store->mattr, attrM_off);
		attrM->count = 0;
		attrM->first_seen = attrM->last_seen = *tv;
		attrM->argc = tkn_count;
		bmvec_u64_set(hs->ptn_store->attr_idx, ptn_id, attrM_off);
	}

	attrM_off = bmvec_u64_get(hs->ptn_store->attr_idx, ptn_id);
	attrM = BMPTR(hs->ptn_store->mattr, attrM_off);
	assert(attrM);

	attrM->count++;
	if (timercmp(tv, &attrM->first_seen, <))
		attrM->first_seen = *tv;

	if (timercmp(tv, &attrM->last_seen, >))
		attrM->last_seen = *tv;

	pthread_mutex_unlock(&hs->ptn_store->mutex);
	return ptn_id;

 err_2:
	/* Unset pattern attribute */
	do {
		void *tmp = NULL;
		barray_set(hs->ptn_store->aattr, ptn_id, &tmp);
	} while (0);
 err_1:
	bptn_attr_free(attr);
 err_0:
	errno = ENOMEM;
	pthread_mutex_unlock(&hs->ptn_store->mutex);
	return 0;
}

/**
 * Add a new token for a pattern if the token is not already present
 * at that position
 */

static int __ptn_tkn_add(bstore_htbl_t hs, bptn_id_t ptn_id,
			 uint64_t tkn_pos, btkn_id_t tkn_id,
			 struct bptn_attr *attr,
			 struct bptn_attrM *attrM)
{
	int rc;
	struct bmlnode_u32 *elm;
	uint64_t elm_off;

	if (!barray_get(hs->ptn_store->aattr, ptn_id, &attr))
		return ENOENT;
	rc = bset_u32_insert(&attr->arg[tkn_pos], (uint32_t)tkn_id);
	switch (rc) {
	case 0:
		/* New data, add into mmapped arg list too. */
		elm_off = bmem_alloc(hs->ptn_store->marg, sizeof(*elm));
		if (!elm_off) {
			bset_u32_remove(&attr->arg[tkn_pos], (uint32_t)tkn_id);
			rc = ENOMEM;
			break;
		}
		elm = BMPTR(hs->ptn_store->marg, elm_off);
		elm->data = (uint32_t)tkn_id;
		BMLIST_INSERT_HEAD(attrM->arg_off[tkn_pos],
				   elm,
				   link,
				   hs->ptn_store->marg);
		break;
	case EEXIST:
		/* Do nothing */
		break;
	default: /* Error */
		break;
	}
	return rc;
}

static int bs_ptn_tkn_add(bstore_t bs, bptn_id_t ptn_id,
			  uint64_t tkn_pos, btkn_id_t tkn_id)
{
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	struct bptn_attr *attr;
	uint64_t attrM_off;
	struct bptn_attrM *attrM;
	int rc;

	pthread_mutex_lock(&hs->ptn_store->mutex);
	if (!barray_get(hs->ptn_store->aattr, ptn_id, &attr)) {
		rc = ENOENT;
		goto out;
	}
	attrM_off = bmvec_u64_get(hs->ptn_store->attr_idx, ptn_id);
	attrM = BMPTR(hs->ptn_store->mattr, attrM_off);
	rc = __ptn_tkn_add(hs, ptn_id, tkn_pos, tkn_id, attr, attrM);
 out:
	pthread_mutex_unlock(&hs->ptn_store->mutex);
	return rc;
}


static int bs_msg_add(bstore_t bs, struct timeval *tv, bmsg_t bmsg)
{
	bstore_htbl_t hs = (bstore_htbl_t)bs;
	struct bptn_attr *attr;
	uint64_t attrM_off;
	struct bptn_attrM *attrM;
	int rc;
	size_t len;
	size_t req_len;
	sos_array_t msg;
	sos_obj_t obj;
	int arg;
	SOS_KEY(tc_key);
	SOS_KEY(ptc_key);
	ods_key_value_t tc_kv = tc_key->as.ptr;
	ods_key_value_t ptc_kv = ptc_key->as.ptr;
	struct bsos_msg_key_ptc *ptc_k = (struct bsos_msg_key_ptc *)ptc_kv->value;
	struct bsos_msg_key_tc *tc_k = (struct bsos_msg_key_tc *)tc_kv->value;

	pthread_mutex_lock(&hs->sos_mutex);
	obj = sos_array_obj_new(hs->sos_msg->sos, SOS_TYPE_UINT32_ARRAY,
				bmsg->argc + BSOS_MSG_ARGV_0);
	if (!obj) {
		rc = ENOMEM;
		goto err0;
	}
	/* setting object value */
	msg = sos_obj_ptr(obj);
	msg->data.uint32_[BSOS_MSG_SEC] = tv->tv_sec;
	msg->data.uint32_[BSOS_MSG_USEC] = tv->tv_usec;
	msg->data.uint32_[BSOS_MSG_COMP_ID] = (uint32_t)bmsg->comp_id;
	msg->data.uint32_[BSOS_MSG_PTN_ID] = (uint32_t)bmsg->ptn_id;

	barray_get(hs->ptn_store->aattr, bmsg->ptn_id, &attr);
	assert(attr);
	attrM_off = bmvec_u64_get(hs->ptn_store->attr_idx, bmsg->ptn_id);
	attrM = BMPTR(hs->ptn_store->mattr, attrM_off);
	for (arg = 0; arg < bmsg->argc; arg++) {
		msg->data.uint32_[arg + BSOS_MSG_ARGV_0] = (uint32_t)bmsg->argv[arg];
		rc = __ptn_tkn_add(hs, bmsg->ptn_id,
				   arg, bmsg->argv[arg] >> 8,
				   attr, attrM);
	}

	/* create keys */
	ptc_k->comp_id = htobe32(bmsg->comp_id);
	ptc_k->sec = htobe32(tv->tv_sec);
	ptc_k->ptn_id = htobe32(bmsg->ptn_id);
	ptc_kv->len = 24;

	tc_k->comp_id = bmsg->comp_id;
	tc_k->sec = tv->tv_sec;
	tc_kv->len = 8;

	/* add into Time-CompID index */
	rc = sos_index_insert(hs->sos_msg->index_tc, tc_key, obj);
	if (rc)
		goto err1;

	/* add into PtnID-Time-CompID index */
	rc = sos_index_insert(hs->sos_msg->index_ptc, ptc_key, obj);
	if (rc)
		goto err2;
	sos_obj_put(obj);
	pthread_mutex_unlock(&hs->sos_mutex);
	return 0;

 err2:
	sos_index_remove(hs->sos_msg->index_tc, tc_key, obj);
 err1:
	sos_obj_delete(obj);
	sos_obj_put(obj);
	pthread_mutex_unlock(&hs->sos_mutex);
 err0:
	return rc;
}

static btkn_t bs_ptn_tkn_iter_find(bptn_tkn_iter_t iter,
				   bptn_id_t ptn_id, uint64_t tkn_pos)
{
	bstore_htbl_t hs = (bstore_htbl_t)iter->bs;
	bhtbl_iter_t i = (bhtbl_iter_t)iter;
	uint64_t attrM_off;
	struct bptn_attrM *attrM;
	uint64_t elm_off;
	btkn_id_t tkn_id;

	attrM_off = bmvec_u64_get(hs->ptn_store->attr_idx, ptn_id);
	if (!attrM_off)
		return NULL;

	attrM = BMPTR(hs->ptn_store->mattr, attrM_off);
	if (!attrM)
		return NULL;

	i->ptn_tkn_elm = BMPTR(hs->ptn_store->marg, attrM->arg_off[tkn_pos]);
	if (!i->ptn_tkn_elm)
		return NULL;

	tkn_id = (btkn_id_t)i->ptn_tkn_elm->data;
	return bs_tkn_find_by_id(iter->bs, tkn_id);
}

static btkn_t bs_ptn_tkn_iter_next(bptn_tkn_iter_t iter)
{
	bstore_htbl_t hs = (bstore_htbl_t)iter->bs;
	bhtbl_iter_t i = (bhtbl_iter_t)iter;
	btkn_id_t tkn_id;

	i->ptn_tkn_elm = BMLIST_NEXT(i->ptn_tkn_elm, link, hs->ptn_store->marg);
	if (i->ptn_tkn_elm) {
		tkn_id = i->ptn_tkn_elm->data;
		return bs_tkn_find_by_id(iter->bs, tkn_id);
	}
	return NULL;
}

static struct bstore_plugin_s plugin = {
	.open = bs_open,
	.close = bs_close,

	.tkn_add = bs_tkn_add,
	.tkn_add_with_id = bs_tkn_add_with_id,
	.tkn_find_by_id = bs_tkn_find_by_id,
	.tkn_find_by_name = bs_tkn_find_by_name,
	.tkn_iter_new = bs_tkn_iter_new,
	.tkn_iter_free = bs_tkn_iter_free,
	.tkn_iter_card = bs_tkn_iter_card,
	.tkn_iter_first = bs_tkn_iter_first,
	.tkn_iter_next = bs_tkn_iter_next,

	.msg_add = bs_msg_add,
	.msg_iter_new = bs_msg_iter_new,
	.msg_iter_free = bs_msg_iter_free,
	.msg_iter_card = bs_msg_iter_card,
	.msg_iter_find = bs_msg_iter_find,
	.msg_iter_first = bs_msg_iter_first,
	.msg_iter_last = bs_msg_iter_last,
	.msg_iter_next = bs_msg_iter_next,
	.msg_iter_prev = bs_msg_iter_prev,

	.ptn_add = bs_ptn_add,
	.ptn_find = bs_ptn_find,
	.ptn_iter_new = bs_ptn_iter_new,
	.ptn_iter_free = bs_ptn_iter_free,
	.ptn_iter_card = bs_ptn_iter_card,
	.ptn_iter_find = bs_ptn_iter_find,
	.ptn_iter_first = bs_ptn_iter_first,
	.ptn_iter_last = bs_ptn_iter_last,
	.ptn_iter_next = bs_ptn_iter_next,
	.ptn_iter_prev = bs_ptn_iter_prev,

	.ptn_tkn_iter_new = bs_ptn_tkn_iter_new,
	.ptn_tkn_iter_free = bs_ptn_tkn_iter_free,
	.ptn_tkn_iter_card = bs_ptn_tkn_iter_card,
	.ptn_tkn_iter_find = bs_ptn_tkn_iter_find,
	.ptn_tkn_iter_next = bs_ptn_tkn_iter_next
};

bstore_plugin_t init_store(void)
{
	return &plugin;
}
