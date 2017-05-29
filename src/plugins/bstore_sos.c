#undef _GNU_SOURCE
#define _GNU_SOURCE

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
#include "baler/bstore.h"
#include "baler/butils.h"

#ifdef __be64
#pragma message "WARNING: __be64 is already defined!"
#else
#define __be64
#define __be32
#endif

int bstore_lock = 1;

time_t clamp_time_to_bin(time_t time_, uint32_t bin_width)
{
	return (time_ / bin_width) * bin_width;
}

typedef struct bstore_sos_s {
	struct bstore_s base;
	sos_t dict_sos;
	sos_t ptn_sos;
	sos_t ptn_tkn_sos;
	sos_t msg_sos;
	sos_t hist_sos;
	sos_schema_t token_value_schema;
	sos_schema_t message_schema;
	sos_schema_t pattern_schema;
	sos_schema_t pattern_token_schema;
	sos_schema_t token_hist_schema;
	sos_schema_t pattern_hist_schema;
	sos_schema_t component_hist_schema;

	sos_attr_t tkn_id_attr; /* Token.tkn_id */
	sos_attr_t tkn_type_mask_attr; /* Token.tkn_type_mask */
	sos_attr_t tkn_text_attr; /* Token.tkn_text */

	sos_attr_t pt_key_attr; /* Message.pt_key */
	sos_attr_t ct_key_attr; /* Message.ct_key */
	sos_attr_t tc_key_attr; /* Message.tc_key */

	sos_attr_t tkn_ids_attr;  /* Message.tkn_ids */
	sos_attr_t ptn_id_attr;	  /* Pattern.ptn_id */
	sos_attr_t first_seen_attr;	  /* Pattern.first_seen */
	sos_attr_t tkn_type_ids_attr; /* Pattern.tkn_type_ids */
	sos_attr_t ptn_pos_tkn_key_attr;  /* PatternToken.ptn_pos_tkn_key */

	sos_attr_t tkn_hist_key_attr;
	sos_attr_t ptn_hist_key_attr;
	sos_attr_t comp_hist_key_attr;

	btkn_id_t next_tkn_id;
	bptn_id_t next_ptn_id;

	pthread_mutex_t dict_lock;
	pthread_mutex_t msg_lock;
	pthread_mutex_t ptn_lock;
	pthread_mutex_t ptn_tkn_lock;
	pthread_mutex_t hist_lock;
} *bstore_sos_t;

struct sos_schema_template token_value_schema = {
	.name = "TokenValue",
	.attrs = {
		{
			.name = "tkn_id",
			.type = SOS_TYPE_UINT64,
			.indexed = 1,
			.idx_type = "HTBL",
		},
		{ /* one bit for each type seen for this text (0..63)*/
			.name = "tkn_type_mask",
			.type = SOS_TYPE_UINT64,
		},
		{
			.name = "tkn_count",
			.type = SOS_TYPE_UINT64,
		},
		{
			.name = "tkn_text",
			.type = SOS_TYPE_CHAR_ARRAY,
			.indexed = 1,
			.idx_type = "HTBL",
		},
		{ NULL }
	}
};

typedef struct tkn_value_s {
	uint64_t tkn_id;
	uint64_t tkn_type_mask;
	uint64_t tkn_count;
	union sos_obj_ref_s tkn_text;
} *tkn_value_t;

#define MSG_IDX_TYPE "BXTREE"
#define MSG_IDX_ARGS "ORDER=5 SIZE=7"
struct sos_schema_template message_schema = {
	.name = "Message",
	.attrs = {
		{	/* ptn_id:usecs */
			.name = "pt_key",
			.type = SOS_TYPE_STRUCT,
			.size = 16,
			.indexed = 1,
			.key_type = "UINT128",
			.idx_type = MSG_IDX_TYPE,
			.idx_args = MSG_IDX_ARGS,
		},
		{	/* comp_id:usecs */
			.name = "ct_key",
			.type = SOS_TYPE_STRUCT,
			.size = 16,
			.indexed = 1,
			.key_type = "UINT128",
			.idx_type = MSG_IDX_TYPE,
			.idx_args = MSG_IDX_ARGS,
		},
		{	/* usecs:comp_id */
			.name = "tc_key",
			.type = SOS_TYPE_STRUCT,
			.size = 16,
			.indexed = 1,
			.key_type = "UINT128",
			.idx_type = MSG_IDX_TYPE,
			.idx_args = MSG_IDX_ARGS,
		},
		{
			.name = "tkn_count",
			.type = SOS_TYPE_UINT64,
		},
		{
			.name = "tkn_ids",
			.type = SOS_TYPE_BYTE_ARRAY
		},
		{ NULL }
	}
};

struct pt_msg_key {
	__be64 uint64_t ptn_id;
	__be64 uint64_t usecs;
};
struct tc_msg_key {
	__be64 uint64_t usecs;
	__be64 uint64_t comp_id;
};
struct ct_msg_key {
	__be64 uint64_t comp_id;
	__be64 uint64_t usecs;
};
typedef struct __attribute__ ((__packed__)) msg_s {
	struct pt_msg_key pt_key;	/* ptn + time */
	struct ct_msg_key ct_key;	/* comp + time */
	struct tc_msg_key tc_key;	/* time + comp */
	uint64_t tkn_count;
	union sos_obj_ref_s tkn_ids;
} *msg_t;

struct sos_schema_template pattern_schema = {
	.name = "Pattern",
	.attrs = {
		{
			.name = "ptn_id",
			.type = SOS_TYPE_UINT64,
			.indexed = 1,
			.idx_type = "BXTREE",
		},
		{
			.name = "first_seen",
			.type = SOS_TYPE_TIMESTAMP,
			.indexed = 1,
		},
		{
			.name = "last_seen",
			.type = SOS_TYPE_TIMESTAMP,
		},
		{
			.name = "count",
			.type = SOS_TYPE_UINT64,
		},
		{
			.name = "tkn_count",
			.type = SOS_TYPE_UINT64,
		},
		{
			.name = "tkn_type_ids",
			.type = SOS_TYPE_BYTE_ARRAY,
			.indexed = 1,
			.idx_type = "HTBL",
		},
		{ NULL }
	}
};

typedef struct ptn_s {
	uint64_t ptn_id;
	struct sos_timestamp_s first_seen;
	struct sos_timestamp_s last_seen;
	uint64_t count;
	uint64_t tkn_count;
	union sos_obj_ref_s tkn_type_ids;
} *ptn_t;

struct sos_schema_template pattern_token_schema = {
	.name = "PatternToken",
	.attrs = {
		{
			.name = "ptn_pos_tkn_key",
			.type = SOS_TYPE_STRUCT,
			.indexed = 1,
			// .idx_type = "H2BXT",
			.idx_type = "BXTREE",
			.idx_args = "ORDER=5 SIZE=3",
			.size = 24,
			.key_type = "MEMCMP",
		},
		{
			.name = "count",
			.type = SOS_TYPE_UINT64,
		},
		{ NULL }
	}
};

#pragma pack(4)
typedef struct ptn_pos_tkn_s {
	struct {
		__be64 uint64_t ptn_id;
		__be64 uint64_t pos;
		__be64 uint64_t tkn_id;
	} key;
	// uint64_t count;
} *ptn_pos_tkn_t;
#pragma pop()

// #define HIST_IDX "H2BXT"
#define HIST_IDX "BXTREE"
#define HIST_IDX_ARGS "ORDER=5 SIZE=19"

struct sos_schema_template token_hist_schema = {
	.name = "TokenHist",
	.attrs = {
		{
			.name = "tkn_hist_key",
			.type = SOS_TYPE_STRUCT,
			.size = 16,
			.indexed = 1,
			.idx_type = HIST_IDX,
			.idx_args = HIST_IDX_ARGS,
			.key_type = "MEMCMP",
		},
		{
			.name = "count",
			.type = SOS_TYPE_UINT64,
		},
		{ NULL }
	}
};

#pragma pack(4)
typedef struct tkn_hist_s {
	struct {
		__be32 uint32_t bin_width;
		__be32 uint32_t time;
		__be64 uint64_t tkn_id;
	} key;
	// uint64_t count;
} *tkn_hist_t;
#pragma pop()

static inline
void tkn_hist_htobe(tkn_hist_t tkn_h)
{
	tkn_h->key.bin_width = htobe32(tkn_h->key.bin_width);
	tkn_h->key.time = htobe32(tkn_h->key.time);
	tkn_h->key.tkn_id = htobe64(tkn_h->key.tkn_id);
}

static inline
void tkn_hist_betoh(tkn_hist_t tkn_h)
{
	tkn_h->key.bin_width = be32toh(tkn_h->key.bin_width);
	tkn_h->key.time = be32toh(tkn_h->key.time);
	tkn_h->key.tkn_id = be64toh(tkn_h->key.tkn_id);
}

struct sos_schema_template pattern_hist_schema = {
	.name = "PatternHist",
	.attrs = {
		{
			.name = "ptn_hist_key",
			.type = SOS_TYPE_STRUCT,
			.size = 16,
			.indexed = 1,
			.idx_type = HIST_IDX,
			.idx_args = HIST_IDX_ARGS,
			.key_type = "MEMCMP",
		},
		{
			.name = "count",
			.type = SOS_TYPE_UINT64,
		},
		{ NULL }
	}
};

#pragma pack(4)
typedef struct ptn_hist_s {
	struct {
		__be32 uint32_t bin_width;
		__be32 uint32_t time;
		__be64 uint64_t ptn_id;
	} key;
	// uint64_t count;
} *ptn_hist_t;
#pragma pop()

static inline
void ptn_hist_htobe(ptn_hist_t ptn_h)
{
	ptn_h->key.bin_width = htobe32(ptn_h->key.bin_width);
	ptn_h->key.time = htobe32(ptn_h->key.time);
	ptn_h->key.ptn_id = htobe64(ptn_h->key.ptn_id);
}

static inline
void ptn_hist_betoh(ptn_hist_t ptn_h)
{
	ptn_h->key.bin_width = be32toh(ptn_h->key.bin_width);
	ptn_h->key.time = be32toh(ptn_h->key.time);
	ptn_h->key.ptn_id = be64toh(ptn_h->key.ptn_id);
}

struct sos_schema_template component_hist_schema = {
	.name = "ComponentHist",
	.attrs = {
		{
			.name = "comp_hist_key",
			.type = SOS_TYPE_STRUCT,
			.size = 24,
			.indexed = 1,
			.idx_type = HIST_IDX,
			.idx_args = HIST_IDX_ARGS,
			.key_type = "MEMCMP"
		},
		{
			.name = "count",
			.type = SOS_TYPE_UINT64,
		},
		{ NULL }
	}
};

#pragma pack(4)
typedef struct comp_hist_s {
	struct {
		__be32 uint32_t bin_width;
		__be32 uint32_t time;
		__be64 uint64_t comp_id;
		__be64 uint64_t ptn_id;
	} key;
	// uint64_t count;
} *comp_hist_t;
#pragma pop()

static inline
void comp_hist_htobe(comp_hist_t comp_h)
{
	comp_h->key.bin_width = htobe32(comp_h->key.bin_width);
	comp_h->key.time = htobe32(comp_h->key.time);
	comp_h->key.ptn_id = htobe64(comp_h->key.ptn_id);
	comp_h->key.comp_id = htobe64(comp_h->key.comp_id);
}

static inline
void comp_hist_betoh(comp_hist_t comp_h)
{
	comp_h->key.bin_width = be32toh(comp_h->key.bin_width);
	comp_h->key.time = be32toh(comp_h->key.time);
	comp_h->key.ptn_id = be64toh(comp_h->key.ptn_id);
	comp_h->key.comp_id = be64toh(comp_h->key.comp_id);
}

static size_t encode_id(uint64_t id, uint8_t *s);
static size_t encoded_id_len(uint64_t id);
static size_t decode_ptn(bstr_t ptn, const uint8_t *tkn_str, size_t tkn_count);
static size_t decode_msg(bmsg_t msg, const uint8_t *tkn_str, size_t tkn_count);
static btkn_id_t bs_tkn_add(bstore_t bs, btkn_t tkn);
static int bs_tkn_add_with_id(bstore_t bs, btkn_t tkn);
static size_t encode_ptn(bstr_t ptn, size_t tkn_count);

static sos_t create_container(const char *path, int o_mode)
{
	sos_t sos;
	sos_part_t part;
	int rc;

	rc = sos_container_new(path, o_mode);
	if (rc)
		return NULL;
	sos = sos_container_open(path, SOS_PERM_RW);
	if (!sos)
		return NULL;
	rc = sos_part_create(sos, "ROOT", path);
	if (rc)
		goto err;
	part = sos_part_find(sos, "ROOT");
	if (!part)
		goto err;
	rc = sos_part_state_set(part, SOS_PART_STATE_PRIMARY);
	sos_part_put(part);
	if (rc)
		goto err;
	return sos;
 err:
	sos_container_close(sos, SOS_COMMIT_ASYNC);
	return NULL;
}

static int create_store(const char *path, int o_mode)
{
	sos_part_t part;
	sos_t dict, msgs, ptns, ptn_tkns, hist;
	sos_schema_t schema;
	int rc = ENOMEM;
	char *cpath = malloc(PATH_MAX);
	if (!cpath)
		goto err_0;

	/*
	 * Dictionary Store
	 */
	sprintf(cpath, "%s/Dictionary", path);
	dict = create_container(cpath, o_mode);
	if (!dict)
		goto err_1;
	schema = sos_schema_from_template(&token_value_schema);
	rc = sos_schema_add(dict, schema);
	if (rc)
		goto err_2;
	/*
	 * Patterns
	 */
	sprintf(cpath, "%s/Patterns", path);
	ptns = create_container(cpath, o_mode);
	if (!ptns)
		goto err_2;
	schema = sos_schema_from_template(&pattern_schema);
	rc = sos_schema_add(ptns, schema);
	if (rc)
		goto err_3;

	/*
	 * Messages
	 */
	sprintf(cpath, "%s/Messages", path);
	msgs = create_container(cpath, o_mode);
	if (!msgs)
		goto err_3;
	schema = sos_schema_from_template(&message_schema);
	rc = sos_schema_add(msgs, schema);
	if (rc)
		goto err_4;

	/*
	 * Pattern Tokens
	 */
	sprintf(cpath, "%s/PatternTokens", path);
	ptn_tkns = create_container(cpath, o_mode);
	if (!ptn_tkns)
		goto err_4;
	schema = sos_schema_from_template(&pattern_token_schema);
	rc = sos_schema_add(ptn_tkns, schema);
	if (rc)
		goto err_5;

	/*
	 * History
	 */
	sprintf(cpath, "%s/History", path);
	hist = create_container(cpath, o_mode);
	if (!hist)
		goto err_5;
	schema = sos_schema_from_template(&token_hist_schema);
	rc = sos_schema_add(hist, schema);
	if (rc)
		goto err_6;
	schema = sos_schema_from_template(&pattern_hist_schema);
	rc = sos_schema_add(hist, schema);
	if (rc)
		goto err_6;
	schema = sos_schema_from_template(&component_hist_schema);
	rc = sos_schema_add(hist, schema);
	if (rc)
		goto err_6;
	free(cpath);
	sos_container_close(hist, SOS_COMMIT_ASYNC);
	sos_container_close(msgs, SOS_COMMIT_ASYNC);
	sos_container_close(ptns, SOS_COMMIT_ASYNC);
	sos_container_close(dict, SOS_COMMIT_ASYNC);
	return 0;
 err_6:
	sos_container_close(hist, SOS_COMMIT_ASYNC);
 err_5:
	sos_container_close(ptn_tkns, SOS_COMMIT_ASYNC);
 err_4:
	sos_container_close(msgs, SOS_COMMIT_ASYNC);
 err_3:
	sos_container_close(ptns, SOS_COMMIT_ASYNC);
 err_2:
	sos_container_close(dict, SOS_COMMIT_ASYNC);
 err_1:
	free(cpath);
 err_0:
	return rc;
}

static int __tkn_cmp_fn(void *a, const void *b)
{
	return strcmp(a, b);
}

static int __cnt_cmp_fn(void *a, const void *b)
{
	uint64_t aa = *(uint64_t *)a;
	uint64_t bb = *(uint64_t *)b;
	if (aa < bb)
		return -1;
	else if (aa > bb)
		return 1;
	return 0;
}

static bstore_t bs_open(bstore_plugin_t plugin, const char *path, int flags, int o_mode)
{
	int create = 0;
	sos_perm_t perm;
	int rc;
	char *cpath;
	bstore_sos_t bs;
	bs = calloc(1, sizeof(*bs));
	if (!bs)
		goto err_0;
	bs->base.plugin = plugin;
	bs->base.path = strdup(path);
	if (!bs->base.path)
		goto err_1;

	/* Open the Root container */
	cpath = malloc(PATH_MAX);
	if (!cpath)
		goto err_2;

	/*
	 * Open the BalerDict store containing the token definitions and tokens
	 */
	sprintf(cpath, "%s/Dictionary", path);
 reopen:
	perm = (flags & O_RDWR ? SOS_PERM_RW : SOS_PERM_RO);
	bs->dict_sos = sos_container_open(cpath, SOS_PERM_RW);
	if (!bs->dict_sos) {
		if (0 == (flags & O_CREAT))
			goto err_3;
		rc = create_store(path, o_mode);
		if (!rc) {
			create = 1;
			flags &= ~O_CREAT;
			goto reopen;
		}
		goto err_3;
	}
	bs->token_value_schema = sos_schema_by_name(bs->dict_sos, "TokenValue");
	if (!bs->token_value_schema)
		goto err_4;
	bs->tkn_id_attr = sos_schema_attr_by_name(bs->token_value_schema, "tkn_id");
	if (!bs->tkn_id_attr)
		goto err_4;
	bs->tkn_type_mask_attr =
		sos_schema_attr_by_name(bs->token_value_schema, "tkn_type_mask");
	if (!bs->tkn_type_mask_attr)
		goto err_4;
	bs->tkn_text_attr = sos_schema_attr_by_name(bs->token_value_schema, "tkn_text");
	if (!bs->tkn_text_attr)
		goto err_4;

	/*
	 * Open the Message container
	 */
	sprintf(cpath, "%s/Messages", path);
	bs->msg_sos = sos_container_open(cpath, SOS_PERM_RW);
	if (!bs->msg_sos)
		goto err_4;
	bs->message_schema = sos_schema_by_name(bs->msg_sos, "Message");
	if (!bs->message_schema)
		goto err_5;
	bs->pt_key_attr = sos_schema_attr_by_name(bs->message_schema, "pt_key");
	if (!bs->pt_key_attr)
		goto err_5;
	bs->ct_key_attr = sos_schema_attr_by_name(bs->message_schema, "ct_key");
	if (!bs->pt_key_attr)
		goto err_5;
	bs->tc_key_attr = sos_schema_attr_by_name(bs->message_schema, "tc_key");
	if (!bs->tc_key_attr)
		goto err_5;
	bs->tkn_ids_attr = sos_schema_attr_by_name(bs->message_schema, "tkn_ids");
	if (!bs->tkn_ids_attr)
		goto err_5;


	sprintf(cpath, "%s/Patterns", path);
	bs->ptn_sos = sos_container_open(cpath, SOS_PERM_RW);
	if (!bs->ptn_sos)
		goto err_5;
	bs->pattern_schema = sos_schema_by_name(bs->ptn_sos, "Pattern");
	if (!bs->pattern_schema)
		goto err_6;
	bs->ptn_id_attr = sos_schema_attr_by_name(bs->pattern_schema, "ptn_id");
	if (!bs->ptn_id_attr)
		goto err_6;
	bs->first_seen_attr = sos_schema_attr_by_name(bs->pattern_schema, "first_seen");
	if (!bs->first_seen_attr)
		goto err_6;
	bs->tkn_type_ids_attr =
		sos_schema_attr_by_name(bs->pattern_schema, "tkn_type_ids");
	if (!bs->tkn_type_ids_attr)
		goto err_6;

	sprintf(cpath, "%s/PatternTokens", path);
	bs->ptn_tkn_sos = sos_container_open(cpath, SOS_PERM_RW);
	if (!bs->ptn_tkn_sos)
		goto err_6;
	bs->pattern_token_schema = sos_schema_by_name(bs->ptn_tkn_sos, "PatternToken");
	if (!bs->pattern_token_schema)
		goto err_7;
	bs->ptn_pos_tkn_key_attr =
		sos_schema_attr_by_name(bs->pattern_token_schema, "ptn_pos_tkn_key");
	if (!bs->ptn_pos_tkn_key_attr)
		goto err_7;

	sprintf(cpath, "%s/History", path);
	bs->hist_sos = sos_container_open(cpath, SOS_PERM_RW);
	if (!bs->hist_sos)
		goto err_7;
	bs->token_hist_schema = sos_schema_by_name(bs->hist_sos, "TokenHist");
	if (!bs->token_hist_schema)
		goto err_8;
	bs->tkn_hist_key_attr =
		sos_schema_attr_by_name(bs->token_hist_schema, "tkn_hist_key");
	if (!bs->tkn_hist_key_attr)
		goto err_8;

	bs->pattern_hist_schema = sos_schema_by_name(bs->hist_sos, "PatternHist");
	if (!bs->pattern_hist_schema)
		goto err_8;
	bs->ptn_hist_key_attr =
		sos_schema_attr_by_name(bs->pattern_hist_schema, "ptn_hist_key");
	if (!bs->ptn_hist_key_attr)
		goto err_8;

	bs->component_hist_schema = sos_schema_by_name(bs->hist_sos, "ComponentHist");
	if (!bs->component_hist_schema)
		goto err_8;
	bs->comp_hist_key_attr =
		sos_schema_attr_by_name(bs->component_hist_schema, "comp_hist_key");
	if (!bs->comp_hist_key_attr)
		goto err_8;

	/* Compute the next token and pattern ids */
	sos_iter_t iter = sos_attr_iter_new(bs->tkn_id_attr);
	if (!iter)
		goto err_8;
	rc = sos_iter_end(iter);
	if (rc) {
		bs->next_tkn_id = 0x0100;
	} else {
		sos_obj_t last = sos_iter_obj(iter);
		tkn_value_t tv = sos_obj_ptr(last);
		bs->next_tkn_id = tv->tkn_id;
		if (bs->next_tkn_id < 0x0100)
			bs->next_tkn_id = 0x0100;
		sos_obj_put(last);
	}
	sos_iter_free(iter);
	iter = sos_attr_iter_new(bs->ptn_id_attr);
	if (!iter)
		goto err_8;
	rc = sos_iter_end(iter);
	if (rc) {
		bs->next_ptn_id = 0x0100;
	} else {
		sos_obj_t last = sos_iter_obj(iter);
		ptn_t ptn = sos_obj_ptr(last);
		bs->next_ptn_id = ptn->ptn_id + 1;
		sos_obj_put(last);
	}
	sos_iter_free(iter);
	pthread_mutex_init(&bs->dict_lock, NULL);
	pthread_mutex_init(&bs->msg_lock, NULL);
	pthread_mutex_init(&bs->ptn_lock, NULL);
	pthread_mutex_init(&bs->ptn_tkn_lock, NULL);
	pthread_mutex_init(&bs->hist_lock, NULL);
	if (!create)
		goto out;
	/*
	 * We created the container, add the token-type tokens. For
	 * these special tokens, the tkn_type_id == tkn_id.
	 */
	btkn_type_t type;
	for (type = BTKN_TYPE_FIRST+1; type < BTKN_TYPE_LAST_BUILTIN; type++) {
		char type_name[80];
		btkn_t tkn;
		btkn_id_t tkn_id;
		sprintf(type_name, "_%s_", btkn_attr_type_str(type));
		tkn = btkn_alloc(type, BTKN_TYPE_MASK(type), type_name, strlen(type_name));
		tkn->tkn_type_mask |= BTKN_TYPE_MASK(BTKN_TYPE_TYPE);
		rc = bs_tkn_add_with_id(&bs->base, tkn);
		assert(0 == rc);
		btkn_free(tkn);
	}
 out:
	free(cpath);
	return &bs->base;
 err_8:
	sos_container_close(bs->hist_sos, SOS_COMMIT_ASYNC);
 err_7:
	sos_container_close(bs->ptn_tkn_sos, SOS_COMMIT_ASYNC);
 err_6:
	sos_container_close(bs->ptn_sos, SOS_COMMIT_ASYNC);
 err_5:
	sos_container_close(bs->msg_sos, SOS_COMMIT_ASYNC);
 err_4:
	sos_container_close(bs->dict_sos, SOS_COMMIT_ASYNC);
 err_3:
	free(cpath);
 err_2:
	free(bs->base.path);
 err_1:
	free(bs);
 err_0:
	return NULL;
}

static void bs_close(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	if (!bs)
		return;
	free(bs->path);
	sos_container_close(bss->dict_sos, SOS_COMMIT_ASYNC);
	sos_container_close(bss->ptn_sos, SOS_COMMIT_ASYNC);
	sos_container_close(bss->ptn_tkn_sos, SOS_COMMIT_ASYNC);
	sos_container_close(bss->msg_sos, SOS_COMMIT_ASYNC);
	sos_container_close(bss->hist_sos, SOS_COMMIT_ASYNC);
	free(bs);
}

struct token_value_s {
	uint64_t tkn_type_id;
	uint64_t tkn_id;
	union sos_obj_ref_s tkn_text;
};

/*
 * The token id is formatted as follows:
 *
 * 00:XX:XX:XX:XX:XX:XX:TT
 *  ^                    ^
 *  |                    +-- encodes the token type
 *  +---- must be zero in order to ensure an encoded token <= 8B
 *
 * This leaves 6B to encode the unique id or 281474976710656 (281T)
 * unique token values.
 *
 * The purpose for encoding the type in the lower byte is so
 * that a token saved in a message will also encode it's type which
 * provides for richer output formatting options without having to
 * also look up the pattern.
 */
static btkn_id_t allocate_tkn_id(bstore_sos_t bss)
{
	btkn_id_t tkn_id = bss->next_tkn_id;
	tkn_id = bss->next_tkn_id;
	bss->next_tkn_id = tkn_id + 1;
	return tkn_id;
}

static bptn_id_t allocate_ptn_id(bstore_sos_t bss)
{
	bptn_id_t ptn_id = __sync_fetch_and_add(&bss->next_ptn_id, 1);
	return ptn_id;
}

static size_t encode_text_with_id(char *dst, uint64_t id, const char *text, size_t len)
{
	size_t sz = encode_id(id, (void*)&dst[1]);
	assert(sz < 256);
	dst[0] = (uint8_t)sz;
	memcpy(&dst[sz+1], text, len);
	return sz + len + 1;
}

static void encode_tkn_key(sos_key_t key, const char *text, size_t text_len)
{
	ods_key_value_t kv = key->as.ptr;
	memcpy(kv->value, text, text_len);
	kv->value[text_len] = '\0';
	kv->len = text_len + 1;
}

static int __add_tkn_with_id(bstore_sos_t bss, btkn_t tkn, uint64_t count)
{
	int rc;
	tkn_value_t tkn_value;
	struct sos_value_s v_, *v;
	size_t sz;
	sos_obj_t tkn_obj;

	/* Allocate a new object */
	tkn_obj = sos_obj_new(bss->token_value_schema);
	if (!tkn_obj)
		goto err_0;
	tkn_value = sos_obj_ptr(tkn_obj);
	tkn_value->tkn_count = count;

	sz = tkn->tkn_str->blen + 1;
	v = sos_array_new(&v_, bss->tkn_text_attr, tkn_obj, sz);
	if (!v)
		goto err_1;
	memcpy(v->data->array.data.byte_, tkn->tkn_str->cstr, sz);
	sos_value_put(v);
	tkn_value->tkn_id = tkn->tkn_id;
	/* Squash BTKN_TYPE_TEXT (i.e. unrecognized) if WORD or
	 * HOSTNAME is present */
	if (btkn_has_type(tkn, BTKN_TYPE_WORD)
	    | btkn_has_type(tkn, BTKN_TYPE_HOSTNAME))
		tkn->tkn_type_mask &= ~BTKN_TYPE_MASK(BTKN_TYPE_TEXT);
	tkn_value->tkn_type_mask = tkn->tkn_type_mask;
	rc = sos_obj_index(tkn_obj);
	if (rc)
		goto err_1;
 out:
	sos_obj_put(tkn_obj);
	return 0;
 err_1:
	sos_obj_delete(tkn_obj);
	sos_obj_put(tkn_obj);
 err_0:
	return rc;
}

struct missing_cb_ctxt {
	bstore_sos_t bss;
	sos_obj_t obj;
	btkn_t tkn;
};

// #define MEM_TOKENS 1
static sos_visit_action_t tkn_add_cb(sos_index_t index,
				     sos_key_t key, sos_idx_data_t *idx_data,
				     int found, void *arg)
{
	int rc;
	tkn_value_t tkn_value;
	struct sos_value_s v_, *v;
	size_t sz;
	sos_obj_t tkn_obj;
	sos_obj_ref_t *ref = (sos_obj_ref_t *)idx_data;
	struct missing_cb_ctxt *ctxt = arg;
	btkn_id_t tkn_id;
	SOS_KEY(id_key);

	if (found) {
#ifdef MEM_TOKENS
		assert(0 == "Shouldn't be adding this token");
#endif
		tkn_obj = sos_ref_as_obj(ctxt->bss->dict_sos, *ref);
		/* Update the token value */
		tkn_value = sos_obj_ptr(tkn_obj);
		tkn_value->tkn_count++;
		tkn_value->tkn_type_mask |= ctxt->tkn->tkn_type_mask;
		/* Update the memory tkn */
		ctxt->tkn->tkn_id = tkn_value->tkn_id;
		ctxt->tkn->tkn_type_mask = tkn_value->tkn_type_mask;
		sos_obj_put(tkn_obj);
		return SOS_VISIT_NOP;
	}

	/* Allocate a new object */
	tkn_obj = sos_obj_new(ctxt->bss->token_value_schema);
	if (!tkn_obj)
		goto err_0;

	tkn_value = sos_obj_ptr(tkn_obj);
	tkn_value->tkn_count = ctxt->tkn->tkn_count;

	sz = ctxt->tkn->tkn_str->blen+1;
	v = sos_array_new(&v_, ctxt->bss->tkn_text_attr, tkn_obj, sz);
	if (!v)
		goto err_1;

	memcpy(v->data->array.data.byte_, ctxt->tkn->tkn_str->cstr, sz-1);
	v->data->array.data.byte_[ctxt->tkn->tkn_str->blen] = '\0';
	sos_value_put(v);

	/* Squash BTKN_TYPE_TEXT (i.e. unrecognized) if WORD or
	 * HOSTNAME is present */
	if (btkn_has_type(ctxt->tkn, BTKN_TYPE_WORD)
	    | btkn_has_type(ctxt->tkn, BTKN_TYPE_HOSTNAME))
		ctxt->tkn->tkn_type_mask &= ~BTKN_TYPE_MASK(BTKN_TYPE_TEXT);
	tkn_value->tkn_type_mask = ctxt->tkn->tkn_type_mask;
	// pthread_mutex_lock(&ctxt->bss->lock);
	tkn_id = allocate_tkn_id(ctxt->bss);
	// pthread_mutex_unlock(&ctxt->bss->lock);
	ctxt->tkn->tkn_id = tkn_value->tkn_id = tkn_id;
	sos_key_set(id_key, &tkn_id, sizeof(tkn_id));
	sos_index_insert(sos_attr_index(ctxt->bss->tkn_id_attr), id_key, tkn_obj);

 out:
	ctxt->obj = sos_obj_get(tkn_obj);
	*ref = sos_obj_ref(tkn_obj);
	sos_obj_put(tkn_obj);
	return SOS_VISIT_ADD;
 err_1:
	assert(0 == "Failed to allocate array");
	sos_obj_delete(tkn_obj);
	sos_obj_put(tkn_obj);
 err_0:
	return SOS_VISIT_NOP;
}

static btkn_id_t bs_tkn_add(bstore_t bs, btkn_t tkn)
{
	int rc;
	bstore_sos_t bss = (bstore_sos_t)bs;
	struct missing_cb_ctxt ctxt = {0};
	SOS_KEY(text_key);
	if (bstore_lock)
		pthread_mutex_lock(&bss->dict_lock);

	/* If the token is already added, return it's id */
	encode_tkn_key(text_key, tkn->tkn_str->cstr, tkn->tkn_str->blen);
	ctxt.bss = bss;
	ctxt.tkn = tkn;
	rc = sos_index_visit(sos_attr_index(bss->tkn_text_attr), text_key,
			     tkn_add_cb, &ctxt);

	sos_obj_put(ctxt.obj);
	if (bstore_lock)
		pthread_mutex_unlock(&bss->dict_lock);
	return ctxt.tkn->tkn_id;
}

static int bs_tkn_add_with_id(bstore_t bs, btkn_t tkn)
{
	int rc;
	sos_obj_t tkn_obj;
	bstore_sos_t bss = (bstore_sos_t)bs;
	SOS_KEY(text_key);

	if (bstore_lock)
		pthread_mutex_lock(&bss->dict_lock);
	encode_tkn_key(text_key, tkn->tkn_str->cstr, tkn->tkn_str->blen);
	/* If the token is already added, return an error */
	tkn_obj = sos_obj_find(bss->tkn_text_attr, text_key);
	if (tkn_obj) {
		sos_obj_put(tkn_obj);
		rc = ENOENT;
		goto err_0;
	}
	rc = __add_tkn_with_id(bss, tkn, 0);
 err_0:
	if (bstore_lock)
		pthread_mutex_unlock(&bss->dict_lock);
	return rc;
}

static btkn_t bs_tkn_find_by_id(bstore_t bs, btkn_id_t tkn_id)
{
	btkn_t token = NULL;
	int rc;
	tkn_value_t tkn_value;
	bstore_sos_t bss = (bstore_sos_t)bs;
	sos_obj_t tkn_obj;
	sos_value_t tkn_str;
	SOS_KEY(id_key);

	sos_key_set(id_key, &tkn_id, sizeof(tkn_id));
	if (bstore_lock)
		pthread_mutex_lock(&bss->dict_lock);
	tkn_obj = sos_obj_find(bss->tkn_id_attr, id_key);
	if (!tkn_obj)
		goto out_0;
	tkn_value = sos_obj_ptr(tkn_obj);
	if (!tkn_value)
		goto out_0;
	tkn_str = sos_value(tkn_obj, bss->tkn_text_attr);
	char *text = tkn_str->data->array.data.char_;
	token = btkn_alloc(tkn_value->tkn_id, tkn_value->tkn_type_mask,
			   text, tkn_str->data->array.count - 1);
	if (token)
		token->tkn_count = tkn_value->tkn_count;
	else
		errno = ENOMEM;
	sos_value_put(tkn_str);
	sos_obj_put(tkn_obj);
 out_0:
	if (bstore_lock)
		pthread_mutex_unlock(&bss->dict_lock);
	return token;
}

static btkn_t bs_tkn_find_by_name(bstore_t bs,
				     const char *text, size_t text_len)
{
	btkn_t token = NULL;
	btkn_id_t tkn_id = 0;
	tkn_value_t tkn_value;
	bstore_sos_t bss = (bstore_sos_t)bs;
	sos_obj_t tkn_obj;
	sos_value_t tkn_str;
	SOS_KEY(text_key);

	encode_tkn_key(text_key, text, text_len);
	if (bstore_lock)
		pthread_mutex_lock(&bss->dict_lock);
	tkn_obj = sos_obj_find(bss->tkn_text_attr, text_key);
	if (!tkn_obj)
		goto out_0;
	tkn_value = sos_obj_ptr(tkn_obj);
	if (!tkn_value)
		goto out_0;
	token = btkn_alloc(tkn_value->tkn_id, tkn_value->tkn_type_mask, text, text_len);
	if (token)
		token->tkn_count = tkn_value->tkn_count;
	else
		errno = ENOMEM;
 out_1:
	sos_obj_put(tkn_obj);
 out_0:
	if (bstore_lock)
		pthread_mutex_unlock(&bss->dict_lock);
	return token;
}

static btkn_type_t bs_tkn_type_get(bstore_t bs, const char *typ_name, size_t name_len)
{
	char *type_name;
	btkn_t btkn;
	btkn_type_t type_id;
	bstore_sos_t bss = (bstore_sos_t)bs;

	name_len = name_len + 3;
	type_name = malloc(name_len);
	if (!type_name) {
		errno = ENOMEM;
		return 0;
	}
	snprintf(type_name, name_len, "_%s_", typ_name);
	if (bstore_lock)
		pthread_mutex_lock(&bss->dict_lock);
	btkn = bs_tkn_find_by_name(bs, type_name, name_len);
	if (!btkn) {
		errno = ENOENT;
		type_id = 0;
		goto out;
	}
	type_id = btkn->tkn_id;
	btkn_free(btkn);
 out:
	if (bstore_lock)
		pthread_mutex_unlock(&bss->dict_lock);
	return type_id;
}

#define TKN_ITER		0x01

#define MSG_ITER_PTN_TIME	0x11
#define MSG_ITER_COMP_TIME	0x12
#define MSG_ITER_TIME_COMP	0x13

#define PTN_ITER_ID		0x21
#define PTN_ITER_FIRST_SEEN	0x22

#define PTN_TKN_ITER		0x31
#define TKN_HIST_ITER		0x41
#define PTN_HIST_ITER		0x51
#define COMP_HIST_ITER		0x61

typedef struct bsos_iter_s {
	bstore_t bs;
	bstore_iter_type_t biter_type; /* bstore iter type */
	/* extension */
	int iter_type; /* internal iter type */
	sos_iter_t iter;
	bmsg_cmp_fn_t cmp_fn;
	struct bstore_iter_filter_s filter;
	btkn_id_t ptn_tkn_id; /* used in ptn_tkn_iter */
	void *cmp_ctxt;
} *bsos_iter_t;

typedef struct bsos_iter_pos_s {
	struct bstore_iter_pos_s base;
	int iter_type;
	struct bstore_iter_filter_s filter;
	btkn_id_t ptn_tkn_id;
	sos_pos_t sos_pos;
} *bsos_iter_pos_t;

static bstore_iter_pos_t __iter_pos_get(bsos_iter_t iter)
{
	int rc;
	size_t sz;
	sos_pos_t sos_pos;
	struct bsos_iter_pos_s *pos;
	if (!iter->iter)
		goto err_0;
	rc = sos_iter_pos_get(iter->iter, &sos_pos);
	if (rc)
		goto err_0;
	sz = sizeof(*pos) + sizeof(sos_pos);
	pos = malloc(sz);
	if (!pos)
		goto err_1;
	pos->base.type = iter->biter_type;
	pos->iter_type = iter->iter_type;
	pos->filter = iter->filter;
	switch (iter->iter_type) {
	case TKN_ITER:
	case PTN_ITER_ID:
	case PTN_ITER_FIRST_SEEN:
	case MSG_ITER_PTN_TIME:
	case MSG_ITER_COMP_TIME:
	case MSG_ITER_TIME_COMP:
	case PTN_TKN_ITER:
	case TKN_HIST_ITER:
	case PTN_HIST_ITER:
	case COMP_HIST_ITER:
		break;
	default:
		assert(0 == "Unknown iterator type");
		errno = EINVAL;
		goto err_2;
	}
	pos->base.data_len = sz - sizeof(pos->base);
	memcpy(&pos->sos_pos, &sos_pos, sizeof(sos_pos));
	return &pos->base;

 err_2:
	free(pos);
 err_1:
	sos_iter_pos_put(iter->iter, sos_pos);
 err_0:
	return NULL;
}

static int __iter_pos_set(bsos_iter_t iter, bsos_iter_pos_t pos)
{
	sos_pos_t sos_pos = pos->sos_pos;
	/* recovering the filter parameters first */
	iter->filter = pos->filter;
	free(pos); /* pos is a 1-time use */
	return sos_iter_pos_set(iter->iter, sos_pos);
}

static bstore_iter_pos_t bs_tkn_iter_pos_get(btkn_iter_t iter)
{
	return __iter_pos_get((bsos_iter_t)iter);
}

static int bs_tkn_iter_pos_set(btkn_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;
	/* If the sos_iter already exists and is the correct type, use it */
	if (!i->iter || (i->iter_type != pos->iter_type))
		return ENOENT;
	return __iter_pos_set(i, pos);
}

static void bs_tkn_iter_pos_free(btkn_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;
	if ((iter->type != _pos->type) || (i->iter_type != pos->iter_type)) {
		assert(0 == "Iterator - Position type mismatch");
		return;
	}
	sos_iter_pos_put(i->iter, pos->sos_pos);
	free(pos);
}

static btkn_iter_t bs_tkn_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t ti = calloc(1, sizeof(*ti));
	if (ti) {
		ti->bs = bs;
		ti->biter_type = BTKN_ITER;
		ti->iter_type = TKN_ITER;
		ti->iter = sos_attr_iter_new(bss->tkn_id_attr);
		if (!ti->iter)
			goto err;
		sos_iter_flags_set(ti->iter, SOS_ITER_F_INF_LAST_DUP);
	}
	return (btkn_iter_t)ti;
 err:
	free(ti);
	return NULL;
}

static void bs_tkn_iter_free(btkn_iter_t i)
{
	bsos_iter_t ti = (bsos_iter_t)i;
	if (ti->iter)
		sos_iter_free(ti->iter);
	free(i);
}

static uint64_t bs_tkn_iter_card(btkn_iter_t i)
{
	bsos_iter_t ti = (bsos_iter_t)i;
	if (ti->iter)
		return sos_iter_card(ti->iter);
	return 0;
}

static btkn_t __make_tkn(bstore_sos_t bss, sos_obj_t tkn_obj)
{
	struct sos_value_s v_, *v;
	tkn_value_t tv;
	btkn_t tkn;
	size_t txt_len;
	size_t skip_len;

	if (!tkn_obj)
		return NULL;

	tv = sos_obj_ptr(tkn_obj);
	v = sos_value_init(&v_, tkn_obj, bss->tkn_text_attr);
	if (!v)
		goto out;

	txt_len = sos_array_count(v) - 1; /* the null byte '\0' is included
					   * in the array_count */
	tkn = btkn_alloc(tv->tkn_id, tv->tkn_type_mask,
			 v->data->array.data.char_,
			 txt_len);
	tkn->tkn_count = tv->tkn_count;
	sos_value_put(v);
	sos_obj_put(tkn_obj);
	return tkn;

 out:
	sos_obj_put(tkn_obj);
	return NULL;
}

static int bs_tkn_iter_first(btkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	return sos_iter_begin(i->iter);
}

static btkn_t bs_tkn_iter_obj(btkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	return __make_tkn(bss, sos_iter_obj(i->iter));
}

static int bs_tkn_iter_next(btkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	return sos_iter_next(i->iter);
}

static int bs_tkn_iter_prev(btkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	return sos_iter_prev(i->iter);
}

static int bs_tkn_iter_last(btkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	return sos_iter_end(i->iter);
}

static bstore_iter_pos_t bs_ptn_iter_pos_get(bptn_iter_t iter)
{
	return __iter_pos_get((bsos_iter_t)iter);
}

static int bs_ptn_iter_pos_set(bptn_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;
	bstore_sos_t bss = (bstore_sos_t)i->bs;

	/* If the sos_iter already exists and is the correct type, use it */
	if (i->iter && i->iter_type == pos->iter_type)
		goto set_pos;
	/* Free the existing iterator if present */
	if (i->iter) {
		sos_iter_free(i->iter);
		i->iter = NULL;
	}
	/* Allocate a new iterator of the correct type */
	switch (pos->iter_type) {
	case PTN_ITER_ID:
		i->iter_type = PTN_ITER_ID;
		i->iter = sos_attr_iter_new(bss->ptn_id_attr);
		break;
	case PTN_ITER_FIRST_SEEN:
		i->iter_type = PTN_ITER_FIRST_SEEN;
		i->iter = sos_attr_iter_new(bss->first_seen_attr);
		break;
	default:
		return ENOENT;
	}
	if (!i->iter)
		return ENOENT;
	sos_iter_flags_set(i->iter, SOS_ITER_F_INF_LAST_DUP);
 set_pos:
	return __iter_pos_set(i, pos);
}

static void bs_ptn_iter_pos_free(btkn_iter_t iter, bstore_iter_pos_t _pos)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	sos_iter_t sos_iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;

	if (iter->type != _pos->type) {
		assert(0 == "Iterator - Position type mismatch");
		return;
	}

	switch (pos->iter_type) {
	case PTN_ITER_ID:
		sos_iter = sos_attr_iter_new(bss->ptn_id_attr);
		break;
	case PTN_ITER_FIRST_SEEN:
		sos_iter = sos_attr_iter_new(bss->first_seen_attr);
		break;
	default:
		assert(0 == "Unknown bstore_sos ptn_iter type");
		return;
	}
	if (!sos_iter) {
		assert(0 == "Cannot allocate sos_iter");
		return;
	}
	sos_iter_pos_put(sos_iter, pos->sos_pos);
	free(pos);
}

static bptn_iter_t bs_ptn_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t pi = calloc(1, sizeof(*pi));
	if (pi)
		pi->bs = bs;
	pi->biter_type = BPTN_ITER;
	pi->iter_type = PTN_ITER_ID;
	pi->iter = sos_attr_iter_new(bss->ptn_id_attr);
	if (!pi->iter) {
		free(pi);
		return NULL;
	}
	sos_iter_flags_set(pi->iter, SOS_ITER_F_INF_LAST_DUP);
	return (bptn_iter_t)pi;
}

static void bs_ptn_iter_free(bptn_iter_t i)
{
	bsos_iter_t pi = (bsos_iter_t)i;
	if (pi->iter)
		sos_iter_free(pi->iter);
	free(i);
}

static int bs_ptn_iter_filter_set(bptn_iter_t i, bstore_iter_filter_t f)
{
	bsos_iter_t pi = (bsos_iter_t)i;
	pi->filter = *f;
	return 0;
}

static uint64_t bs_ptn_iter_card(bptn_iter_t i)
{
	bsos_iter_t pi = (bsos_iter_t)i;
	if (pi->iter)
		return sos_iter_card(pi->iter);
	return 0;
}

static bptn_t __make_ptn(bstore_sos_t bss, bsos_iter_t i, sos_obj_t ptn_obj)
{
	struct sos_value_s v_, *tkn_str;
	int rc;
	tkn_value_t tv;
	bptn_t ptn;
	ptn_t sptn;
	size_t txt_len;

	if (!ptn_obj)
		return NULL;

	sptn = sos_obj_ptr(ptn_obj);
	if (i && i->filter.ptn_id > 0) {
		if (sptn->ptn_id != i->filter.ptn_id)
			goto out;
	}
	tkn_str = sos_value_init(&v_, ptn_obj, bss->tkn_type_ids_attr);
	if (!tkn_str)
		goto out;

	ptn = bptn_alloc(sptn->tkn_count);
	if (!ptn)
		goto out;

	ptn->ptn_id = sptn->ptn_id;
	ptn->first_seen.tv_sec = sptn->first_seen.secs;
	ptn->first_seen.tv_usec = sptn->first_seen.usecs;
	ptn->last_seen.tv_sec = sptn->last_seen.secs;
	ptn->last_seen.tv_usec = sptn->last_seen.usecs;
	ptn->count = sptn->count;
	ptn->tkn_count = sptn->tkn_count;
	decode_ptn(ptn->str, tkn_str->data->array.data.byte_, sptn->tkn_count);

	sos_value_put(tkn_str);
	sos_obj_put(ptn_obj);
	return ptn;

 out:
	sos_obj_put(ptn_obj);
	return NULL;
}

static bptn_t bs_ptn_find(bstore_t bs, bptn_id_t ptn_id)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bptn_t ptn = NULL;
	sos_obj_t ptn_obj;
	SOS_KEY(ptn_key);

	sos_key_set(ptn_key, &ptn_id, sizeof(ptn_id));
	ptn_obj = sos_obj_find(bss->ptn_id_attr, ptn_key);
	sos_key_put(ptn_key);
	if (!ptn_obj)
		goto out;
	ptn = __make_ptn(bss, NULL, ptn_obj);
 out:
	return ptn;
}

static int bs_ptn_find_by_ptnstr(bstore_t bs, bptn_t ptn)
{
	bptn_id_t ptn_id;
	ptn_t ptn_value;
	bstore_sos_t bss = (bstore_sos_t)bs;
	sos_obj_t ptn_obj;
	SOS_KEY_SZ(stack_key, 2048);
	sos_key_t ptn_key;
	bstr_t tmp_bstr;
	int rc;

	if (ptn->tkn_count != ptn->str->blen/sizeof(uint64_t)) {
		assert(0); /* for debugging */
		return EINVAL;
	}

	/* dup ptn because we will modify ptn->str */
	tmp_bstr = bstr_dup(ptn->str);
	if (!tmp_bstr) {
		rc = ENOMEM;
		goto out;
	}

	if (ptn->str->blen <= 2048)
		ptn_key = stack_key;
	else
		ptn_key = sos_key_new(tmp_bstr->blen);
	if (!ptn_key) {
		rc = ENOMEM;
		goto cleanup_1;
	}

	size_t ptn_size = encode_ptn(tmp_bstr, ptn->tkn_count);

	sos_key_set(ptn_key, tmp_bstr->cstr, ptn_size);
	if (bstore_lock)
		pthread_mutex_lock(&bss->ptn_lock);

	/* find & copy ptn info from the store to ptn */
	ptn_obj = sos_obj_find(bss->tkn_type_ids_attr, ptn_key);
	if (ptn_key != stack_key)
		sos_key_put(ptn_key);
	if (!ptn_obj) {
		rc = ENOENT;
		goto cleanup_2;
	}
	ptn_value = sos_obj_ptr(ptn_obj);
	ptn->ptn_id = ptn_value->ptn_id;
	ptn->count = ptn_value->count;
	ptn->first_seen.tv_sec = ptn_value->first_seen.secs;
	ptn->first_seen.tv_usec = ptn_value->first_seen.usecs;
	ptn->last_seen.tv_sec = ptn_value->last_seen.secs;
	ptn->last_seen.tv_usec = ptn_value->last_seen.usecs;
	sos_obj_put(ptn_obj);
	rc = 0;
	/* let-through for clean-up */

 cleanup_2:
	if (bstore_lock)
		pthread_mutex_unlock(&bss->ptn_lock);
 cleanup_1:
	bstr_free(tmp_bstr);
 out:
	return rc;
}

static int __matching_ptn(bptn_iter_t iter, int fwd)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	ptn_t ptn;
	sos_obj_t obj;
	struct timeval tv;
	int rc = 0;
	int (*iter_step)(sos_iter_t);

	if (!i->filter.tv_begin.tv_sec)
		return 0; /* no filter for ptn_iter */

	iter_step = fwd?sos_iter_next:sos_iter_prev;

	for (;0 == rc; rc = iter_step(i->iter)) {
		obj = sos_iter_obj(i->iter);
		ptn = sos_obj_ptr(obj);
		tv.tv_sec = ptn->first_seen.secs;
		tv.tv_usec = ptn->first_seen.usecs;
		if (timercmp(&i->filter.tv_begin, &tv, <=)) {
			sos_obj_put(obj);
			break;
		}
		sos_obj_put(obj);
	}
	return rc;
}

static int __bs_ptn_iter_find(bptn_iter_t iter, int fwd, bptn_id_t ptn_id)
{
	SOS_KEY(key);
	ods_key_value_t kv = key->as.ptr;
	struct sos_timestamp_s *first_seen;
	bptn_id_t *_ptn_id;
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc;

	_ptn_id = (void*)kv->value;
	kv->len = sizeof(*_ptn_id);
	*_ptn_id = fwd?ptn_id:(ptn_id?ptn_id:-1);
	rc = fwd?sos_iter_sup(i->iter, key):sos_iter_inf(i->iter, key);
	if (rc)
		goto err;
	return __matching_ptn(iter, fwd);

 err:
	return rc;
}

static int bs_ptn_iter_find_fwd(bptn_iter_t iter, bptn_id_t ptn_id)
{
	return __bs_ptn_iter_find(iter, 1, ptn_id);
}

static int bs_ptn_iter_find_rev(bptn_iter_t iter, bptn_id_t ptn_id)
{
	return __bs_ptn_iter_find(iter, 0, ptn_id);
}

static int bs_ptn_iter_first(bptn_iter_t iter)
{
	return __bs_ptn_iter_find(iter, 1, 0);
}

static int bs_ptn_iter_last(bptn_iter_t iter)
{
	return __bs_ptn_iter_find(iter, 0, 0);
}

static bptn_t bs_ptn_iter_obj(bptn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	return __make_ptn(bss, i, sos_iter_obj(i->iter));
}

static int bs_ptn_iter_next(bptn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc = sos_iter_next(i->iter);
	if (rc)
		return rc;
	return __matching_ptn(iter, 1);
}

static int bs_ptn_iter_prev(bptn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc = sos_iter_prev(i->iter);
	if (rc)
		return rc;
	return __matching_ptn(iter, 0);
}

static bstore_iter_pos_t bs_ptn_tkn_iter_pos_get(bptn_tkn_iter_t iter)
{
	return __iter_pos_get((bsos_iter_t)iter);
}

static int bs_ptn_tkn_iter_pos_set(bptn_tkn_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;

	/* If the sos_iter already exists and is the correct type, use it */
	if (!i->iter || (i->iter_type != pos->iter_type))
		return ENOENT;

	return __iter_pos_set(i, pos);
}

static void bs_ptn_tkn_iter_pos_free(bptn_tkn_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;
	if ((iter->type != _pos->type) || (i->iter_type != pos->iter_type)) {
		assert(0 == "Iterator - Position type mismatch");
		return;
	}
	sos_iter_pos_put(i->iter, pos->sos_pos);
	free(pos);
}

static bptn_tkn_iter_t bs_ptn_tkn_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t pti = calloc(1, sizeof(*pti));
	if (pti) {
		pti->bs = bs;
		pti->biter_type = BPTN_TKN_ITER;
		pti->iter_type = PTN_TKN_ITER;
		pti->iter = sos_attr_iter_new(bss->ptn_pos_tkn_key_attr);
		if (!pti->iter)
			goto err;
		sos_iter_flags_set(pti->iter, SOS_ITER_F_INF_LAST_DUP);
	}
	return (bptn_tkn_iter_t)pti;
 err:
	free(pti);
	return NULL;
}

static void bs_ptn_tkn_iter_free(bptn_tkn_iter_t i)
{
	bsos_iter_t pti = (bsos_iter_t)i;
	if (pti->iter)
		sos_iter_free(pti->iter);
	free(pti);
}

static uint64_t bs_ptn_tkn_iter_card(bptn_tkn_iter_t i)
{
	bsos_iter_t pti = malloc(sizeof(*pti));
	return sos_iter_card(((bsos_iter_t)i)->iter);
}

static bstore_iter_pos_t bs_msg_iter_pos_get(bmsg_iter_t iter)
{
	return __iter_pos_get((bsos_iter_t)iter);
}

static int bs_msg_iter_pos_set(bmsg_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;
	bstore_sos_t bss = (bstore_sos_t)i->bs;

	/* If the sos_iter already exists and is the correct type, use it */
	if (i->iter && i->iter_type == pos->iter_type)
		goto set_pos;
	/* Free the existing iterator if present */
	if (i->iter) {
		sos_iter_free(i->iter);
		i->iter = NULL;
	}
	/* Allocate a new iterator of the correct type */
	switch (pos->iter_type) {
	case MSG_ITER_PTN_TIME:
		i->iter_type = MSG_ITER_PTN_TIME;
		i->iter = sos_attr_iter_new(bss->pt_key_attr);
		break;
	case MSG_ITER_COMP_TIME:
		i->iter_type = MSG_ITER_COMP_TIME;
		i->iter = sos_attr_iter_new(bss->ct_key_attr);
		break;
	case MSG_ITER_TIME_COMP:
		i->iter_type = MSG_ITER_TIME_COMP;
		i->iter = sos_attr_iter_new(bss->tc_key_attr);
		break;
	default:
		return ENOENT;
	}
	if (!i->iter)
		return ENOENT;
	sos_iter_flags_set(i->iter, SOS_ITER_F_INF_LAST_DUP);
 set_pos:
	return __iter_pos_set((bsos_iter_t)iter, pos);
}

static void bs_msg_iter_pos_free(btkn_iter_t iter, bstore_iter_pos_t _pos)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	sos_iter_t sos_iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;
	if (iter->type != _pos->type) {
		assert(0 == "Iterator - Position type mismatch");
		return;
	}
	switch (pos->iter_type) {
	case MSG_ITER_PTN_TIME:
		sos_iter = sos_attr_iter_new(bss->pt_key_attr);
		break;
	case MSG_ITER_COMP_TIME:
		sos_iter = sos_attr_iter_new(bss->ct_key_attr);
		break;
	case MSG_ITER_TIME_COMP:
		sos_iter = sos_attr_iter_new(bss->tc_key_attr);
		break;
	default:
		assert(0 == "Unknown bstore_sos message iterator type");
		return;
	}
	if (!sos_iter) {
		assert(0 == "Cannot allocate sos iterator");
		return;
	}
	sos_iter_pos_put(sos_iter, pos->sos_pos);
	sos_iter_free(sos_iter);
	free(pos);
}

static bmsg_iter_t bs_msg_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t mi = calloc(1, sizeof(*mi));
	if (mi)
		mi->bs = bs;
	mi->biter_type = BMSG_ITER;
	return (bmsg_iter_t)mi;
}

static void bs_msg_iter_free(bmsg_iter_t i)
{
	bsos_iter_t mi = (bsos_iter_t)i;
	if (mi->iter)
		sos_iter_free(mi->iter);
	free(mi);
}

static uint64_t bs_msg_iter_card(bmsg_iter_t i)
{
	bsos_iter_t mi = (bsos_iter_t)i;
	if (mi->iter)
		return sos_iter_card(mi->iter);
	return 0;
}

static bmsg_t __make_msg(bstore_sos_t bss, bsos_iter_t i, sos_obj_t msg_obj)
{
	struct sos_value_s v_, *tkn_ids;
	int rc;
	msg_t tv;
	bmsg_t dmsg;
	msg_t smsg;
	size_t txt_len;
	bptn_id_t ptn_id;
	bptn_t ptn = NULL;
	int x, y;

	if (!msg_obj)
		return NULL;
	smsg = sos_obj_ptr(msg_obj);

	ptn_id = be64toh(smsg->pt_key.ptn_id);
	ptn = bs_ptn_find(&bss->base, ptn_id);
	if (!ptn)
		goto out;

	tkn_ids = sos_value_init(&v_, msg_obj, bss->tkn_ids_attr);
	if (!tkn_ids)
		goto out;

	dmsg = malloc(sizeof(*dmsg) + (ptn->tkn_count * sizeof(uint64_t)));
	if (!dmsg)
		goto out;

	dmsg->ptn_id = be64toh(smsg->pt_key.ptn_id);
	uint64_t usecs = be64toh(smsg->pt_key.usecs);
	dmsg->timestamp.tv_sec = usecs / 1000000;
	dmsg->timestamp.tv_usec = usecs % 1000000;
	dmsg->comp_id = be64toh(smsg->ct_key.comp_id);
	dmsg->argc = smsg->tkn_count;
	decode_msg(dmsg, tkn_ids->data->array.data.byte_, smsg->tkn_count);
	/* fill from the back */
	x = dmsg->argc - 1;
	for (y = ptn->tkn_count - 1; y >= 0; y--) {
		btkn_type_t tkn_type = ptn->str->u64str[y] & 0xFF;
		if (btkn_type_is_wildcard(tkn_type)) {
			dmsg->argv[y] = dmsg->argv[x];
			x--;
		} else {
			dmsg->argv[y] = ptn->str->u64str[y];
		}
	}
	assert(y == -1);
	assert(x == -1);
	dmsg->argc = ptn->tkn_count;

	bptn_free(ptn);
	sos_value_put(tkn_ids);
	sos_obj_put(msg_obj);
	return dmsg;
 out:
	sos_obj_put(msg_obj);
	if (ptn)
		bptn_free(ptn);
	return NULL;
}

static sos_obj_t __next_matching_msg(int rc, bsos_iter_t i, int forwards)
{
	msg_t msg;
	uint64_t msg_ptn, msg_time, msg_comp;
	sos_obj_t obj;
	struct timeval tv;

	for (;0 == rc; rc = (forwards ? sos_iter_next(i->iter) : sos_iter_prev(i->iter))) {
		obj = sos_iter_obj(i->iter);
		msg = sos_obj_ptr(obj);
		msg_ptn = be64toh(msg->pt_key.ptn_id);
		msg_time = be64toh(msg->pt_key.usecs);
		tv.tv_sec = msg_time / 1000000;
		tv.tv_usec = msg_time % 1000000;
		msg_comp = be64toh(msg->ct_key.comp_id);

		/* ptn_id specified and doesn't match, exit */
		if (i->filter.ptn_id) {
			/* We're using the pt_msg_key index */
			if (i->filter.ptn_id != msg_ptn)
				goto enoent;

			if (i->filter.tv_begin.tv_sec &&
					timercmp(&tv, &i->filter.tv_begin, <))
				goto enoent;

			if (i->filter.tv_end.tv_sec &&
					timercmp(&i->filter.tv_end, &tv, <))
				goto enoent;

			/* Skip component id's that don't match */
			if (i->filter.comp_id && (i->filter.comp_id != msg_comp)) {
				sos_obj_put(obj);
				continue;
			} else {
				/* matching object */
				break;
			}
		}

		if (i->filter.comp_id && (i->filter.comp_id != msg_comp)) {
			/* We're using the ct_msg_key index. If comp_id doesn't
			 * match, we've completed the iteration
			 */
			goto enoent;
		}

		if (i->filter.tv_begin.tv_sec &&
				timercmp(&tv, &i->filter.tv_begin, <))
			goto enoent;

		if (i->filter.tv_end.tv_sec &&
				timercmp(&i->filter.tv_end, &tv, <))
			goto enoent;

		/* We're using the tc_msg_key index, return the message */
		break;
	}
	if (!rc)
		return obj;
	errno = rc;
	return NULL;
 enoent:
	errno = ENOENT;
	sos_obj_put(obj);
	return NULL;
}

static int
__bs_msg_iter_find(bmsg_iter_t iter, int fwd, const struct timeval *tv,
		     bcomp_id_t comp_id, bptn_id_t ptn_id)
{
	int rc;
	sos_obj_t obj = NULL;
	SOS_KEY(msg_key);
	uint64_t usecs;
	struct pt_msg_key *pt_key;
	struct ct_msg_key *ct_key;
	struct tc_msg_key *tc_key;
	ods_key_value_t kv = msg_key->as.ptr;

	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;

	if (!i->iter) {
		i->iter_type = MSG_ITER_TIME_COMP;
		i->iter = sos_attr_iter_new(bss->tc_key_attr);
		if (!i->iter) {
			rc = errno;
			goto err;
		}
		sos_iter_flags_set(i->iter, SOS_ITER_F_INF_LAST_DUP);
	}

	tv = (tv)?(tv):((fwd)?(&i->filter.tv_begin):(&i->filter.tv_end));
	usecs = tv->tv_sec * 1000000 + tv->tv_usec;
	ptn_id = (ptn_id)?(ptn_id):(i->filter.ptn_id);
	comp_id = (comp_id)?(comp_id):(i->filter.comp_id);
	if (!fwd) {
		/* set default key to max for reverse find */
		if (!usecs)
			usecs = -1;
		if (!ptn_id)
			ptn_id = -1;
		if (!comp_id)
			comp_id = -1;
	}

	switch (i->iter_type) {
	case MSG_ITER_PTN_TIME:
		pt_key = (struct pt_msg_key *)kv->value;
		pt_key->ptn_id = htobe64(ptn_id);
		pt_key->usecs = htobe64(usecs);
		break;
	case MSG_ITER_COMP_TIME:
		ct_key = (struct ct_msg_key *)kv->value;
		ct_key->comp_id = htobe64(comp_id);
		ct_key->usecs = htobe64(usecs);
		break;
	case MSG_ITER_TIME_COMP:
		tc_key = (struct tc_msg_key *)kv->value;
		tc_key->usecs = htobe64(usecs);
		tc_key->comp_id = htobe64(comp_id);
		break;
	default:
		assert(0 == "BAD ITER_TYPE");
		rc = EINVAL;
		goto err;
	}

	kv->len = 16;

	rc = (fwd)?(sos_iter_sup(i->iter, msg_key)):
		   (sos_iter_inf(i->iter, msg_key));
	obj = __next_matching_msg(rc, i, fwd);
	if (!obj) {
		rc = ENOENT;
		goto err;
	}
	sos_obj_put(obj);
	return 0;
 err:
	return rc;
}

static int
bs_msg_iter_find_fwd(bmsg_iter_t iter, const struct timeval *tv,
		     bcomp_id_t comp_id, bptn_id_t ptn_id)
{
	return __bs_msg_iter_find(iter, 1, tv, comp_id, ptn_id);
}

static int
bs_msg_iter_find_rev(bmsg_iter_t iter, const struct timeval *tv,
		     bcomp_id_t comp_id, bptn_id_t ptn_id)
{
	return __bs_msg_iter_find(iter, 0, tv, comp_id, ptn_id);
}

static bmsg_t bs_msg_iter_obj(bmsg_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	sos_obj_t obj = sos_iter_obj(i->iter);
	if (obj)
		return __make_msg(bss, i, obj);
	return NULL;
}

static int bs_msg_iter_first(bmsg_iter_t iter)
{
	return bs_msg_iter_find_fwd(iter, NULL, 0, 0);
}

static int bs_msg_iter_next(bmsg_iter_t iter)
{
	sos_obj_t obj;
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc;
	rc = sos_iter_next(i->iter);
	if (rc)
		return rc;
	obj = __next_matching_msg(rc, i, 1);
	if (obj) {
		sos_obj_put(obj);
		return 0;
	}
	return errno;
}

static int bs_msg_iter_prev(bmsg_iter_t iter)
{
	sos_obj_t obj;
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc;
	rc = sos_iter_prev(i->iter);
	if (rc)
		return rc;
	obj = __next_matching_msg(rc, i, 0);
	if (obj) {
		sos_obj_put(obj);
		return 0;
	}
	return errno;
}

static int bs_msg_iter_last(bmsg_iter_t iter)
{
	return bs_msg_iter_find_rev(iter, NULL, 0, 0);
}

int bs_msg_iter_filter_set(bmsg_iter_t iter, bstore_iter_filter_t filter)
{
	int rc;
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int new_type;

	i->filter = *filter;

	if (filter->ptn_id) {
		new_type = MSG_ITER_PTN_TIME;
	} else if (filter->comp_id) {
		new_type = MSG_ITER_COMP_TIME;
	} else {
		new_type = MSG_ITER_TIME_COMP;
	}

	if (i->iter && i->iter_type == new_type) {
		/* same iterator type, we can use the existing iterator */
		goto out;
	}

	sos_attr_t attr;
	if (i->iter) {
		/* i->iter can be NULL here */
		sos_iter_free(i->iter);
	}
	switch (new_type) {
	case MSG_ITER_PTN_TIME:
		attr = bss->pt_key_attr;
		break;
	case MSG_ITER_COMP_TIME:
		attr = bss->ct_key_attr;
		break;
	case MSG_ITER_TIME_COMP:
		attr = bss->tc_key_attr;
		break;
	}
	i->iter_type = new_type;
	i->iter = sos_attr_iter_new(attr);
	if (!i->iter) {
		return errno;
	}
	sos_iter_flags_set(i->iter, SOS_ITER_F_INF_LAST_DUP);
out:
	return 0;
}

/**
 * A token id is 8B, but the top byte is reserved and must be
 * zero. This to ensure that an encoded token id including it's
 * size byte is never greater than 8B in size.
 */
static size_t encode_id(btkn_id_t id, uint8_t *s)
{
	id = htole64(id);
	union biffle {
		uint32_t u32;
		uint16_t u16;
		uint8_t u8;
	};
	register union biffle *src = (union biffle *)&id;
	register union biffle *dst = (union biffle *)s;
	size_t sz;
	if (!id) {
		*s = '\0';
		return 1;
	}
	sz = (64 + 7 - __builtin_clzl(id)) >> 3;
	assert(sz < 8);
	register size_t cpy = sz;
	if (cpy >= sizeof(uint32_t)) {
		dst->u32 = src->u32;
		dst = (union biffle *)((char *)dst + sizeof(uint32_t));
		src = (union biffle *)((char *)src + sizeof(uint32_t));
		cpy -= sizeof(uint32_t);
	}
	if (cpy >= sizeof(uint16_t)) {
		dst->u16 = src->u16;
		dst = (union biffle *)((char *)dst + sizeof(uint16_t));
		src = (union biffle *)((char *)src + sizeof(uint16_t));
		cpy -= sizeof(uint16_t);
	}
	if (cpy >= sizeof(uint8_t)) {
		dst->u8 = src->u8;
		cpy -= sizeof(uint8_t);
	}
	assert(cpy == 0);
	return sz;
}

static size_t encoded_id_len(btkn_id_t id)
{
	id = htole64(id);
	size_t bytes;
	for (bytes = 0; id; bytes++) {
		id >>= 8;
	}
	return bytes;
}

/**
 * The first byte of the encoded token is the length. The remaining
 * len bytes are the bytes in LE order of the value
 */
static btkn_id_t decode_id(const uint8_t *s)
{
	btkn_id_t id = 0;
	uint8_t len = *s;
	uint8_t i, shift = 0;
	s++;
	for (i = 0; i < len; i++) {
		uint8_t b = *s;
		id |= (uint64_t)b << shift;
		shift += 8;
		s++;
	}
	return id;
}

/**
 * A pattern/message string is a sequence of length/value tokens
 *
 * These functions encode the ptn/msg in place, i.e it encodes the
 * ptn/msg string into the ptn/msg starting at the first token. Since
 * each element of a uint64_t array is >= the size of the largest encoded
 * token, we are guaranteed to have enough room.
 */
static size_t encode_ptn(bstr_t ptn, size_t tkn_count)
{
	int tkn;
	size_t tkn_size;
	size_t ptn_size = 0;
	uint8_t *ptn_str = (void*)ptn->cstr;
	for (tkn = 0; tkn < tkn_count; tkn++) {
		ptn_str++;	/* skip the len byte */
		tkn_size = encode_id(ptn->u64str[tkn], ptn_str);
		assert(tkn_size && tkn_size < 8);
		ptn_str[-1] = tkn_size; /* fill in the len */
		ptn_str += tkn_size;	/* skip to the next token */
		ptn_size += tkn_size + 1;
	}
	return ptn_size;
}

static size_t decode_ptn(bstr_t ptn, const uint8_t *tkn_str, size_t tkn_count)
{
	int tkn;
	uint8_t tkn_sz;
	btkn_id_t tkn_id;
	ptn->blen = 0;
	for (tkn = 0; tkn < tkn_count; tkn++) {
		tkn_id = decode_id(tkn_str);
		assert((tkn_id >= 256)
		       ||
		       (tkn_id < BTKN_TYPE_LAST
			&&
			tkn_id > BTKN_TYPE_FIRST));
		ptn->u64str[tkn] = tkn_id;
		ptn->blen += sizeof(uint64_t);
		tkn_sz = *tkn_str; /* Get the size */
		tkn_str += tkn_sz + 1;
	}
	return tkn;
}

static size_t encode_msg(bmsg_t msg)
{
	int tkn;
	size_t tkn_size;
	size_t msg_size = 0;
	uint8_t *msg_str = (uint8_t *)&msg->argv[0];
	for (tkn = 0; tkn < msg->argc; tkn++) {
		msg_str++;	/* make room for the size */
		tkn_size = encode_id(msg->argv[tkn], msg_str);
		assert(tkn_size < 256);
		msg_str[-1] = (uint8_t)tkn_size;
		msg_size += tkn_size + 1;
		msg_str += tkn_size;	/* skip the next token */
	}
	return msg_size;
}

static size_t decode_msg(bmsg_t msg, const uint8_t *tkn_str, size_t tkn_count)
{
	int tkn;
	uint8_t tkn_sz;
	btkn_id_t tkn_id;
	msg->argc = 0;
	for (tkn = 0; tkn < tkn_count; tkn++) {
		tkn_id = decode_id(tkn_str);
		assert(tkn_id);
		msg->argv[tkn] = tkn_id;
		msg->argc ++;
		tkn_sz = *tkn_str; /* Get the size */
		tkn_str += tkn_sz + 1;
	}
	return tkn;
}

struct ptn_add_cb_ctxt {
	bstore_sos_t bss;
	bptn_id_t ptn_id;
	struct timeval *tv;
	size_t tkn_count;
	size_t ptn_size;
	bstr_t ptn;
};

static sos_visit_action_t ptn_add_cb(sos_index_t index,
				     sos_key_t key, sos_idx_data_t *idx_data,
				     int found, void *arg)
{
	int rc;
	size_t sz;
	sos_obj_t ptn_obj;
	ptn_t ptn_value;
	sos_obj_ref_t *ref = (sos_obj_ref_t *)idx_data;
	struct ptn_add_cb_ctxt *ctxt = arg;
	SOS_KEY(id_key);
	SOS_KEY(ts_key);
	sos_index_t ptn_id_idx = sos_attr_index(ctxt->bss->ptn_id_attr);
	sos_index_t first_seen_idx = sos_attr_index(ctxt->bss->first_seen_attr);

	if (found) {
		struct timeval last_seen;
		struct timeval first_seen;
		ptn_obj = sos_ref_as_obj(ctxt->bss->ptn_sos, *ref);
		ptn_value = sos_obj_ptr(ptn_obj);
		last_seen.tv_sec = ptn_value->last_seen.secs;
		last_seen.tv_usec = ptn_value->last_seen.usecs;
		first_seen.tv_sec = ptn_value->first_seen.secs;
		first_seen.tv_usec = ptn_value->first_seen.usecs;
		if (timercmp(&first_seen, ctxt->tv, >)) {
			/* new first seen is before the db first seen */
			/* remove existing key */
			sos_key_set(ts_key, &ptn_value->first_seen,
						sizeof(&ptn_value->first_seen));
			sos_index_remove(first_seen_idx, ts_key, ptn_obj);
			/* add new key */
			ptn_value->first_seen.secs = ctxt->tv->tv_sec;
			ptn_value->first_seen.usecs = ctxt->tv->tv_usec;
			sos_key_set(ts_key, &ptn_value->first_seen,
						sizeof(&ptn_value->first_seen));
			sos_index_insert(first_seen_idx, ts_key, ptn_obj);
		}
		if (timercmp(&last_seen, ctxt->tv, <)) {
			ptn_value->last_seen.secs = ctxt->tv->tv_sec;
			ptn_value->last_seen.usecs = ctxt->tv->tv_usec;
		}
		ptn_value->count ++;
		ctxt->ptn_id = ptn_value->ptn_id;
		sos_obj_put(ptn_obj);
		return SOS_VISIT_NOP;
	}

	/* Allocate and save this new pattern */
	ptn_obj = sos_obj_new(ctxt->bss->pattern_schema);
	if (!ptn_obj)
		goto err_0;

	ptn_value = sos_obj_ptr(ptn_obj);
	if (!ptn_value)
		goto err_1;

	ptn_value->first_seen.secs = ptn_value->last_seen.secs = ctxt->tv->tv_sec;
	ptn_value->first_seen.usecs = ptn_value->last_seen.usecs = ctxt->tv->tv_usec;
	ptn_value->tkn_count = ctxt->tkn_count;
	ptn_value->count = 1;

	sos_value_t v;
	struct sos_value_s v_;
	v = sos_array_new(&v_, ctxt->bss->tkn_type_ids_attr,
						ptn_obj, ctxt->ptn_size);
	if (!v)
		goto err_1;

	sos_value_memcpy(v, ctxt->ptn->cstr, ctxt->ptn_size);
	sos_value_put(v);
	ctxt->ptn_id = ptn_value->ptn_id = allocate_ptn_id(ctxt->bss);

	/* index the ptn_id */
	sos_key_set(id_key, &ctxt->ptn_id, sizeof(ctxt->ptn_id));
	rc = sos_index_insert(ptn_id_idx, id_key, ptn_obj);
	if (rc)
		goto err_1;

	/* index the first_seen */
	sos_key_set(ts_key, &ptn_value->first_seen, sizeof(&ptn_value->first_seen));
	rc = sos_index_insert(first_seen_idx, ts_key, ptn_obj);
	if (rc)
		goto err_2;

	*ref = sos_obj_ref(ptn_obj);
	sos_obj_put(ptn_obj);
	return SOS_VISIT_ADD;

 err_2:
	sos_index_remove(sos_attr_index(ctxt->bss->ptn_id_attr),
							id_key, ptn_obj);
 err_1:
	sos_obj_delete(ptn_obj);
	sos_obj_put(ptn_obj);
 err_0:
	return SOS_VISIT_NOP;
}

static bptn_id_t bs_ptn_add(bstore_t bs, struct timeval *tv, bstr_t ptn)
{
	bptn_id_t ptn_id;
	ptn_t ptn_value;
	bstore_sos_t bss = (bstore_sos_t)bs;
	sos_obj_t ptn_obj;
	SOS_KEY_SZ(stack_key, 2048);
	sos_key_t ptn_key;
	int rc;
	struct ptn_add_cb_ctxt ctxt = { .bss = bss, .tv = tv, .ptn = ptn };

	if (ptn->blen <= 2048) {
		ptn_key = stack_key;
	} else {
		ptn_key = sos_key_new(ptn->blen);
		if (!ptn_key)
			return 0;
	}

	ctxt.tkn_count = ptn->blen / sizeof(ptn->u64str[0]);
	ctxt.ptn_size = encode_ptn(ptn, ctxt.tkn_count);
	sos_key_set(ptn_key, ptn->cstr, ctxt.ptn_size);

	if (bstore_lock)
		pthread_mutex_lock(&bss->ptn_lock);

	rc = sos_index_visit(sos_attr_index(bss->tkn_type_ids_attr),
						ptn_key, ptn_add_cb, &ctxt);
	if (ptn_key != stack_key)
		sos_key_put(ptn_key);

	if (bstore_lock)
		pthread_mutex_unlock(&bss->ptn_lock);

	if (rc)
		return 0;
	return ctxt.ptn_id;
}

static sos_visit_action_t hist_cb(sos_index_t index,
				  sos_key_t key, sos_idx_data_t *idx_data,
				  int found,
				  void *arg)
{
	if (!found) {
		idx_data->uint64_[1] = 1;
		return SOS_VISIT_ADD;
	}
	idx_data->uint64_[1]++;
	return SOS_VISIT_UPD;
}

/**
 * Add a new token for a pattern if the token is not already present
 * at that position
 */
static int bs_ptn_tkn_add(bstore_t bs, bptn_id_t ptn_id, uint64_t tkn_pos,
			  btkn_id_t tkn_id)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	SOS_KEY(key);
	ods_key_value_t kv = key->as.ptr;
	ptn_pos_tkn_t ppt_k = (ptn_pos_tkn_t)kv->value;
	sos_index_t idx;
	int rc;

	ppt_k->key.ptn_id = htobe64(ptn_id);
	ppt_k->key.pos = htobe64(tkn_pos);
	ppt_k->key.tkn_id = htobe64(tkn_id);
	kv->len = sizeof(ppt_k->key);

	if (bstore_lock)
		pthread_mutex_lock(&bss->ptn_tkn_lock);
	idx = sos_attr_index(bss->ptn_pos_tkn_key_attr);
	rc = sos_index_visit(idx, key, hist_cb, NULL);
	if (bstore_lock)
		pthread_mutex_unlock(&bss->ptn_tkn_lock);
	return rc;
}

static int __bs_static_ptn_tkn_rc(bstore_t bs, bptn_id_t ptn_id,
				  uint64_t tkn_pos, btkn_id_t *tkn_id)
{
	btkn_t tkn;
	bptn_t ptn = NULL;
	btkn_type_t tkn_type;
	btkn_id_t _tkn_id;

	ptn = bs_ptn_find(bs, ptn_id);
	if (!ptn)
		return EINVAL;

	tkn_type = ptn->str->u64str[tkn_pos] & 0xFF;
	_tkn_id = ptn->str->u64str[tkn_pos] >> 8;
	bptn_free(ptn);

	if (btkn_type_is_wildcard(tkn_type)) {
		return ENOKEY;
	}

	/* non-wildcard */

	if (*tkn_id && _tkn_id != *tkn_id) {
		return ENOENT;
	}

	*tkn_id = _tkn_id;

	return 0;
}

/*
 * \retval tkn if the tkn at the tkn_pos is not a wildcard and the tkn_id is
 *         matched (if given).
 * \retval ENOKEY if the tkn at tkn_pos is a wildcard.
 * \retval errno if other error occur.
 */
static btkn_t __bs_static_ptn_tkn(bstore_t bs, bptn_id_t ptn_id,
				  uint64_t tkn_pos, btkn_id_t tkn_id)
{
	btkn_t tkn;
	bptn_t ptn = NULL;
	btkn_type_t tkn_type;
	btkn_id_t _tkn_id;
	uint64_t count;

	ptn = bs_ptn_find(bs, ptn_id);
	if (!ptn)
		return NULL;

	tkn_type = ptn->str->u64str[tkn_pos] & 0xFF;
	_tkn_id = ptn->str->u64str[tkn_pos] >> 8;
	count = ptn->count;
	bptn_free(ptn);

	if (btkn_type_is_wildcard(tkn_type)) {
		errno = ENOKEY;
		return NULL;
	}

	/* non-wildcard */
	if (tkn_id && _tkn_id != tkn_id) {
		errno = ENOENT;
		return NULL;
	}

	tkn = bs_tkn_find_by_id(bs, _tkn_id);
	if (!tkn)
		return NULL;
	tkn->tkn_count = count;
	return tkn;
}

static btkn_t bs_ptn_tkn_find(bstore_t bs, bptn_id_t ptn_id, uint64_t tkn_pos,
			      btkn_id_t tkn_id)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	SOS_KEY(key);
	ods_key_value_t kv = key->as.ptr;
	ptn_pos_tkn_t ppt_k = (ptn_pos_tkn_t)kv->value;
	sos_obj_ref_t ref;
	sos_index_t idx;
	btkn_t tkn;
	int rc;

	tkn = __bs_static_ptn_tkn(bs, ptn_id, tkn_pos, tkn_id);
	if (tkn)
		return tkn;
	if (errno != ENOKEY) /* expect ENOKEY if !tkn */
		return NULL;

	ppt_k->key.ptn_id = htobe64(ptn_id);
	ppt_k->key.pos = htobe64(tkn_pos);
	ppt_k->key.tkn_id = htobe64(tkn_id);
	kv->len = sizeof(ppt_k->key);

	if (bstore_lock)
		pthread_mutex_lock(&bss->ptn_tkn_lock);
	idx = sos_attr_index(bss->ptn_pos_tkn_key_attr);
	rc = sos_index_find_ref(idx, key, &ref);
	if (!rc) {
		tkn = bs_tkn_find_by_id(bs, tkn_id);
		if (!tkn) {
			errno = ENOMEM;
			goto out;
		}
		tkn->tkn_count = ref.idx_data.uint64_[1];
	} else {
		errno = rc;
		tkn = NULL;
	}
 out:
	if (bstore_lock)
		pthread_mutex_unlock(&bss->ptn_tkn_lock);
	return tkn;
}

static int bs_ptn_hist_update(bstore_t bs,
			      bptn_id_t ptn_id, bcomp_id_t comp_id,
			      time_t secs, time_t bin_width)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	SOS_KEY(ph_key);
	ods_key_value_t ph_k = ph_key->as.ptr;
	ptn_hist_t ptn_k = (ptn_hist_t)ph_k->value;
	SOS_KEY(ch_key);
	ods_key_value_t ch_k = ch_key->as.ptr;
	comp_hist_t comp_k = (comp_hist_t)ch_k->value;
	sos_index_t idx;
	int bin, rc;

	ph_k->len = sizeof(ptn_k->key);
	ch_k->len = sizeof(comp_k->key);

	/* Pattern Histogram */
	ptn_k->key.ptn_id = htobe64(ptn_id);
	ptn_k->key.time = htobe32((uint32_t)secs);
	ptn_k->key.bin_width = htobe32((uint32_t)bin_width);
	idx = sos_attr_index(bss->ptn_hist_key_attr);
	rc = sos_index_visit(idx, ph_key, hist_cb, NULL);

	/* Date Histogram */
	ptn_k->key.ptn_id = htobe64(BPTN_ID_SUM_ALL);
	ptn_k->key.time = htobe32((uint32_t)secs);
	ptn_k->key.bin_width = htobe32((uint32_t)bin_width);
	idx = sos_attr_index(bss->ptn_hist_key_attr);
	rc = sos_index_visit(idx, ph_key, hist_cb, NULL);

	/* Component Histogram */
	comp_k->key.comp_id = htobe64(comp_id);
	comp_k->key.ptn_id = htobe64(ptn_id);
	comp_k->key.time = htobe32((uint32_t)secs);
	comp_k->key.bin_width = htobe32(bin_width);
	idx = sos_attr_index(bss->comp_hist_key_attr);
	rc = sos_index_visit(idx, ch_key, hist_cb, NULL);

	return 0;
 err_0:
	// pthread_mutex_unlock(&bss->hist_lock);
	return ENOMEM;
}

static int bs_tkn_hist_update(bstore_t bs, time_t secs, time_t bin_width, btkn_id_t tkn_id)
{
	SOS_KEY(key);
	bstore_sos_t bss = (bstore_sos_t)bs;
	ods_key_value_t hist_k = key->as.ptr;
	tkn_hist_t tkn_k = (tkn_hist_t)hist_k->value;
	sos_index_t idx = sos_attr_index(bss->tkn_hist_key_attr);

	hist_k->len = sizeof(tkn_k->key);
	tkn_k->key.tkn_id = htobe64(tkn_id);
	tkn_k->key.time = htobe32(secs);
	tkn_k->key.bin_width = htobe32(bin_width);
	return sos_index_visit(idx, key, hist_cb, NULL);
}

static int bs_msg_add(bstore_t bs, struct timeval *tv, bmsg_t msg)
{
	msg_t msg_value;
	bstore_sos_t bss = (bstore_sos_t)bs;
	sos_obj_t msg_obj;
	uint64_t pos;
	btkn_type_t type_id;
	int rc = ENOMEM;
	btkn_type_t tkn_type;
	int i, wc;

	/* This code trashes the msg memory */
	msg = bmsg_dup(msg);
	if (!msg)
		return ENOMEM;

	if (bstore_lock)
		pthread_mutex_lock(&bss->msg_lock);

	/* Allocate and save this new message */
	msg_obj = sos_obj_new(bss->message_schema);
	if (!msg_obj)
		goto err_0;

	uint64_t usecs = htobe64(tv->tv_sec * 1000000 + tv->tv_usec);
	msg_value = sos_obj_ptr(msg_obj);
	msg_value->pt_key.usecs = usecs;
	msg_value->ct_key.usecs = usecs;
	msg_value->tc_key.usecs = usecs;
	msg_value->pt_key.ptn_id = htobe64(msg->ptn_id);
	msg_value->ct_key.comp_id = htobe64(msg->comp_id);
	msg_value->tc_key.comp_id = htobe64(msg->comp_id);

	/* Input `msg` is a sequence of token IDs. baler2 stored a message as
	 * <ptn_id, wild_card_arg1, wild_card_arg2, ...> to save some space. So,
	 * we can apply the same idea here. */

	wc = 0;

	for (i = 0; i < msg->argc; i++) {
		tkn_type = msg->argv[i] & 0xFF;
		if (btkn_type_is_wildcard(tkn_type)) {
			/* wc <= i */
			msg->argv[wc] = msg->argv[i];
			wc++;
		}
		/* otherwise, skip */
	}

	assert(wc < msg->argc);
	msg->argc = wc;

	msg_value->tkn_count = msg->argc;

	struct sos_value_s v_, *v;
	size_t bmsg_sz = encode_msg(msg);
	v = sos_array_new(&v_, bss->tkn_ids_attr, msg_obj, bmsg_sz);
	if (!v)
		goto err_1;
	sos_value_memcpy(v, &msg->argv[0], bmsg_sz);
	sos_value_put(v);
	rc = sos_obj_index(msg_obj);
	if (rc)
		goto err_1;
	sos_obj_put(msg_obj);
	if (bstore_lock)
		pthread_mutex_unlock(&bss->msg_lock);
	bmsg_free(msg);
	return 0;
 err_1:
	sos_obj_delete(msg_obj);
	sos_obj_put(msg_obj);
 err_0:
	bmsg_free(msg);
	if (bstore_lock)
		pthread_mutex_unlock(&bss->msg_lock);
	return rc;
}

static int __ptn_tkn_iter_check(bsos_iter_t i)
{
	sos_key_t key;
	bptn_id_t ptn_id;
	uint64_t tkn_pos;
	ptn_pos_tkn_t ppt;
	key = sos_iter_key(i->iter);
	if (!key)
		return errno;
	ppt = (void*)sos_key_value(key);
	ptn_id = be64toh(ppt->key.ptn_id);
	tkn_pos = be64toh(ppt->key.pos);
	sos_key_put(key);
	if ((tkn_pos != i->filter.tkn_pos) || (ptn_id != i->filter.ptn_id))
		return ENOENT;
	return 0;
}

static btkn_t make_ptn_tkn(bsos_iter_t i)
{
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc;
	ptn_pos_tkn_t ppt_o;
	btkn_t tkn;
	bptn_id_t ptn_id_;
	uint64_t tkn_pos_;
	btkn_id_t tkn_id_;
	sos_key_t key_o;
	sos_obj_ref_t ref;

	key_o = sos_iter_key(i->iter);
	if (!key_o)
		goto out;

	ppt_o = (typeof(ppt_o))sos_key_value(key_o);
	ptn_id_ = be64toh(ppt_o->key.ptn_id);
	tkn_pos_ = be64toh(ppt_o->key.pos);
	tkn_id_ = be64toh(ppt_o->key.tkn_id);
	sos_key_put(key_o);

	if ((tkn_pos_ != i->filter.tkn_pos) || (ptn_id_ != i->filter.ptn_id))
		goto out;

	tkn = bs_tkn_find_by_id(i->bs, tkn_id_);
	ref = sos_iter_ref(i->iter);
	tkn->tkn_count = ref.idx_data.uint64_[1];
	return tkn;

 out:
	return NULL;
}

static btkn_t bs_ptn_tkn_iter_obj(bptn_tkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	if (i->ptn_tkn_id)
		return __bs_static_ptn_tkn(iter->bs, i->filter.ptn_id,
					   i->filter.tkn_pos, i->ptn_tkn_id);
	return make_ptn_tkn(i);
}

static int bs_ptn_tkn_iter_first(bptn_tkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	SOS_KEY(key);
	ods_key_value_t kv = key->as.ptr;
	ptn_pos_tkn_t ppt_k = (ptn_pos_tkn_t)kv->value;
	int rc;

	/* Check if this position is not a wild card */
	i->ptn_tkn_id = 0;
	rc = __bs_static_ptn_tkn_rc(iter->bs, i->filter.ptn_id,
				    i->filter.tkn_pos, &i->ptn_tkn_id);
	if (rc == 0) {
		/* static non-wildcard ptn_tkn */
		return 0;
	}
	if (rc != ENOKEY) /* expect ENOKEY if !tkn */
		return rc;
	ppt_k->key.ptn_id = htobe64(i->filter.ptn_id);
	ppt_k->key.pos = htobe64(i->filter.tkn_pos);
	ppt_k->key.tkn_id = 0;
	kv->len = sizeof(ppt_k->key);

	rc = sos_iter_sup(i->iter, key);
	return __ptn_tkn_iter_check(i);
}

static int bs_ptn_tkn_iter_last(bptn_tkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	SOS_KEY(key);
	ods_key_value_t kv = key->as.ptr;
	ptn_pos_tkn_t ppt_k = (ptn_pos_tkn_t)kv->value;
	int rc;

	/* Check if this position is not a wild card */
	i->ptn_tkn_id = 0;
	rc = __bs_static_ptn_tkn_rc(iter->bs, i->filter.ptn_id,
				    i->filter.tkn_pos, &i->ptn_tkn_id);
	if (rc == 0) {
		/* static non-wildcard ptn_tkn */
		return 0;
	}
	if (rc != ENOKEY) /* expect ENOKEY if !tkn */
		return rc;

	ppt_k->key.ptn_id = htobe64(i->filter.ptn_id);
	ppt_k->key.pos = htobe64(i->filter.tkn_pos);
	ppt_k->key.tkn_id = -1;
	kv->len = sizeof(ppt_k->key);

	rc = sos_iter_inf(i->iter, key);
	return __ptn_tkn_iter_check(i);
}

static int bs_ptn_tkn_iter_next(bptn_tkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;
	if (i->ptn_tkn_id) /* this is non-wildcard ptn_tkn */
		return ENOENT;
	rc = sos_iter_next(i->iter);
	if (rc)
		return rc;
	return __ptn_tkn_iter_check(i);
}

static int bs_ptn_tkn_iter_prev(bptn_tkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;
	if (i->ptn_tkn_id) /* this is non-wildcard ptn_tkn */
		return ENOENT;
	rc = sos_iter_prev(i->iter);
	if (rc)
		return rc;
	return __ptn_tkn_iter_check(i);
}

static bstore_iter_pos_t bs_tkn_hist_iter_pos_get(btkn_hist_iter_t iter)
{
	return __iter_pos_get((bsos_iter_t)iter);
}

static int bs_tkn_hist_iter_pos_set(btkn_hist_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;
	/* If the sos_iter already exists and is the correct type, use it */
	if (!i->iter || (i->iter_type != pos->iter_type))
		return ENOENT;
	return __iter_pos_set(i, pos);
}

static void bs_tkn_hist_iter_pos_free(btkn_hist_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;
	if ((iter->type != _pos->type) || (i->iter_type != pos->iter_type)) {
		assert(0 == "Iterator - Position type mismatch");
		return;
	}
	sos_iter_pos_put(i->iter, pos->sos_pos);
	free(pos);
}

btkn_hist_iter_t bs_tkn_hist_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t thi = calloc(1, sizeof(*thi));
	if (thi) {
		thi->bs = bs;
		thi->biter_type = BTKN_HIST_ITER;
		thi->iter_type = TKN_HIST_ITER;
		thi->iter = sos_attr_iter_new(bss->tkn_hist_key_attr);
		if (!thi->iter)
			goto err;
		sos_iter_flags_set(thi->iter, SOS_ITER_F_INF_LAST_DUP);
	}
	return (btkn_hist_iter_t)thi;
 err:
	free(thi);
	return NULL;
}

static void bs_tkn_hist_iter_free(btkn_hist_iter_t i)
{
	bsos_iter_t thi = (bsos_iter_t)i;
	if (thi->iter)
		sos_iter_free(thi->iter);
	free(i);
}

/*
 * Index order is:
 * - bin-width
 * - timestamp
 * - token id
 */
static int __tkn_hist_next(bsos_iter_t i)
{
	int rc = 0;
	struct tkn_hist_s tkn_s;
	sos_key_t key_o = sos_iter_key(i->iter);
	time_t start_time = i->filter.tv_begin.tv_sec;
	time_t end_time = i->filter.tv_end.tv_sec;
	sos_obj_ref_t ref;
	for ( ; 0 == rc;
	      sos_key_put(key_o),
		      key_o = (0 == (rc = sos_iter_next(i->iter))?sos_iter_key(i->iter):NULL)) {

		/* copy-out tkn_s value and convert BE-to-host*/
		tkn_s = *(tkn_hist_t)sos_key_value(key_o);
		tkn_hist_betoh(&tkn_s);

		if (i->filter.bin_width &&
				(i->filter.bin_width != tkn_s.key.bin_width))
			/* Bin width doesn't match, no more matches */
			break;

		if ((start_time && tkn_s.key.time < start_time) ||
				(end_time && end_time <  tkn_s.key.time))
			/* Time doesn't match, no more matches */
			break;

		if (i->filter.tkn_id && (i->filter.tkn_id != tkn_s.key.tkn_id))
			/* tkn id doesn't match, keep looking */
			continue;

		/* Everything matches */
		sos_key_put(key_o);
		return 0;
	}
	if (key_o)
		sos_key_put(key_o);
	return ENOENT;
}

static int __tkn_hist_prev(bsos_iter_t i)
{
	int rc = 0;
	struct tkn_hist_s tkn_s;
	sos_key_t key_o = sos_iter_key(i->iter);
	time_t start_time = i->filter.tv_begin.tv_sec;
	time_t end_time = i->filter.tv_end.tv_sec;
	sos_obj_ref_t ref;
	for ( ; 0 == rc;
	      sos_key_put(key_o),
		      key_o = (0 == (rc = sos_iter_prev(i->iter))?sos_iter_key(i->iter):NULL)) {

		tkn_s = *(tkn_hist_t)sos_key_value(key_o);
		tkn_hist_betoh(&tkn_s);

		if (i->filter.bin_width &&
				(i->filter.bin_width != tkn_s.key.bin_width))
			/* Bin width doesn't match, no more matches */
			break;

		if ((start_time && tkn_s.key.time < start_time) ||
				(end_time && end_time < tkn_s.key.time))
			/* Time doesn't match, no more matches */
			break;

		if (i->filter.tkn_id && (i->filter.tkn_id != tkn_s.key.tkn_id))
			/* tkn id doesn't match, keep looking */
			continue;

		/* Everything matches */
		sos_key_put(key_o);
		return 0;
	}
	if (key_o)
		sos_key_put(key_o);
	return ENOENT;
}

static int
__bs_tkn_hist_iter_find(btkn_hist_iter_t iter, int fwd, btkn_hist_t tkn_h)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	SOS_KEY(key);
	ods_key_value_t hist_k = key->as.ptr;
	tkn_hist_t tkn_k = (tkn_hist_t)hist_k->value;
	sos_obj_t hist_o;
	int (*iter_fn)(sos_iter_t, sos_key_t);
	int (*step_fn)(bsos_iter_t);
	int rc;

	if (fwd) {
		iter_fn = sos_iter_sup;
		step_fn = __tkn_hist_next;
	} else {
		iter_fn = sos_iter_inf;
		step_fn = __tkn_hist_prev;
	}

	tkn_k->key.tkn_id = (tkn_h->tkn_id)?(tkn_h->tkn_id):(i->filter.tkn_id);
	tkn_k->key.bin_width = (tkn_h->bin_width)?(tkn_h->bin_width)
						 :(i->filter.bin_width);
	tkn_k->key.time = (tkn_h->time)?(tkn_h->time)
				       :((fwd)?(i->filter.tv_begin.tv_sec)
					      :(i->filter.tv_end.tv_sec));
	tkn_hist_htobe(tkn_k);
	if (!fwd) {
		if (!tkn_k->key.tkn_id)
			tkn_k->key.tkn_id = -1;
		if (!tkn_k->key.bin_width)
			tkn_k->key.bin_width = -1;
		if (!tkn_k->key.time)
			tkn_k->key.time = -1;
	}
	hist_k->len = sizeof(tkn_k->key);

	rc = iter_fn(i->iter, key);
	if (rc)
		return rc;
	return step_fn(i);
}

static int
bs_tkn_hist_iter_find_fwd(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	return __bs_tkn_hist_iter_find(iter, 1, tkn_h);
}

static int
bs_tkn_hist_iter_find_rev(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	return __bs_tkn_hist_iter_find(iter, 0, tkn_h);
}

static int
bs_tkn_hist_iter_last(btkn_hist_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct btkn_hist_s hist = {
		.bin_width = i->filter.bin_width,
		.time = i->filter.tv_end.tv_sec,
		.tkn_id = i->filter.tkn_id,
	};
	return bs_tkn_hist_iter_find_rev(iter, &hist);
}

static int bs_tkn_hist_iter_first(btkn_hist_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct btkn_hist_s hist = {
		.bin_width = i->filter.bin_width,
		.time = i->filter.tv_begin.tv_sec,
		.tkn_id = i->filter.tkn_id,
	};
	return bs_tkn_hist_iter_find_fwd(iter, &hist);
}

static btkn_hist_t bs_tkn_hist_iter_obj(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	sos_key_t key_o;
	tkn_hist_t tkn_o;
	sos_obj_ref_t ref;

	key_o = sos_iter_key(i->iter);
	if (!key_o)
		return NULL;
	tkn_o = (tkn_hist_t)sos_key_value(key_o);
	tkn_h->tkn_id = be64toh(tkn_o->key.tkn_id);
	tkn_h->bin_width = be32toh(tkn_o->key.bin_width);
	tkn_h->time = be32toh(tkn_o->key.time);
	sos_key_put(key_o);
	ref = sos_iter_ref(i->iter);
	tkn_h->tkn_count = ref.idx_data.uint64_[1];

	return tkn_h;
}

static int bs_tkn_hist_iter_next(btkn_hist_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_next(i->iter);
	if (rc)
		return rc;

	return __tkn_hist_next(i);
}

static int bs_tkn_hist_iter_prev(btkn_hist_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_prev(i->iter);
	if (rc)
		return rc;

	return __tkn_hist_prev(i);
}

static bstore_iter_pos_t bs_ptn_hist_iter_pos_get(bptn_hist_iter_t iter)
{
	return __iter_pos_get((bsos_iter_t)iter);
}

static int bs_ptn_hist_iter_pos_set(bptn_hist_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;
	/* If the sos_iter already exists and is the correct type, use it */
	if (!i->iter || (i->iter_type != pos->iter_type))
		return ENOENT;
	return __iter_pos_set(i, pos);
}

static void bs_ptn_hist_iter_pos_free(bptn_hist_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;
	if ((iter->type != _pos->type) || (i->iter_type != pos->iter_type)) {
		assert(0 == "Iterator - Position type mismatch");
		return;
	}
	sos_iter_pos_put(i->iter, pos->sos_pos);
	free(pos);
}

bptn_hist_iter_t bs_ptn_hist_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t phi = calloc(1, sizeof(*phi));
	if (phi) {
		phi->bs = bs;
		phi->biter_type = BPTN_HIST_ITER;
		phi->iter_type = PTN_HIST_ITER;
		phi->iter = sos_attr_iter_new(bss->ptn_hist_key_attr);
		if (!phi->iter)
			goto err;
		sos_iter_flags_set(phi->iter, SOS_ITER_F_INF_LAST_DUP);
	}
	return (bptn_hist_iter_t)phi;
 err:
	free(phi);
	return NULL;
}

static void bs_ptn_hist_iter_free(bptn_hist_iter_t i)
{
	bsos_iter_t phi = (bsos_iter_t)i;
	if (phi->iter)
		sos_iter_free(phi->iter);
	free(i);
}

int ptn_hist_match(bsos_iter_t i, ptn_hist_t ptn_o)
{
	if ((i->filter.ptn_id && (i->filter.ptn_id != ptn_o->key.ptn_id))
	    || (i->filter.bin_width && (i->filter.bin_width != ptn_o->key.bin_width))) {
		return 0;
	}
	return 1;
}

/*
 * Index order is:
 * - bin_width
 * - timestamp
 * - pattern id
 */
static
int __ptn_hist_next(bsos_iter_t i)
{
	int rc = 0;
	sos_key_t key_o = sos_iter_key(i->iter);
	struct ptn_hist_s ptn_s;
	time_t start_time = i->filter.tv_begin.tv_sec;
	time_t end_time = i->filter.tv_end.tv_sec;
	for ( ; 0 == rc;
	      sos_key_put(key_o),
		      key_o = (0 == (rc = sos_iter_next(i->iter))?sos_iter_key(i->iter):NULL)) {

		/* copy-out key and convert BE-to-host */
		ptn_s = *(ptn_hist_t)sos_key_value(key_o);
		ptn_hist_betoh(&ptn_s);

		if (i->filter.bin_width &&
				(i->filter.bin_width != ptn_s.key.bin_width))
			/* Bin width doesn't match, no more matches */
			break;

		if ((start_time && ptn_s.key.time < start_time) ||
				(end_time && end_time < ptn_s.key.time))
			/* Time doesn't match, no more matches */
			break;
		if (i->filter.ptn_id && (i->filter.ptn_id != ptn_s.key.ptn_id))
			/* ptn id doesn't match, skip mismatch */
			continue;

		/* Everything matches, return it */
		sos_key_put(key_o);
		return 0;
	}
	if (key_o)
		sos_key_put(key_o);
	return ENOENT;
}

static int __ptn_hist_prev(bsos_iter_t i)
{
	int rc = 0;
	sos_key_t key_o = sos_iter_key(i->iter);
	struct ptn_hist_s ptn_s;
	time_t start_time = i->filter.tv_begin.tv_sec;
	time_t end_time = i->filter.tv_end.tv_sec;
	for ( ; 0 == rc;
	      sos_key_put(key_o),
		      key_o = (0 == (rc = sos_iter_prev(i->iter))?sos_iter_key(i->iter):NULL)) {

		/* copy-out key and convert BE-to-host */
		ptn_s = *(ptn_hist_t)sos_key_value(key_o);
		ptn_hist_betoh(&ptn_s);

		if (i->filter.bin_width &&
				(i->filter.bin_width != ptn_s.key.bin_width))
			/* Bin width doesn't match, no more matches */
			break;

		if ((start_time && ptn_s.key.time < start_time) ||
				(end_time && end_time < ptn_s.key.time))
			/* Time doesn't match, no more matches */
			break;

		if (i->filter.ptn_id && (i->filter.ptn_id != ptn_s.key.ptn_id))
			/* ptn id doesn't match, skip mismatch */
			continue;

		/* Everything matches, return it */
		sos_key_put(key_o);
		return 0;
	}
	if (key_o)
		sos_key_put(key_o);
	return ENOENT;
}

static int
__bs_ptn_hist_iter_find(bptn_hist_iter_t iter, int fwd, bptn_hist_t ptn_h)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	SOS_KEY(key);
	ods_key_value_t hist_k = key->as.ptr;
	ptn_hist_t ptn_k = (ptn_hist_t)hist_k->value;
	sos_obj_t hist_o;
	int (*iter_fn)(sos_iter_t, sos_key_t);
	int (*step_fn)(bsos_iter_t);
	int rc;

	if (fwd) {
		iter_fn = sos_iter_sup;
		step_fn = __ptn_hist_next;
	} else {
		iter_fn = sos_iter_inf;
		step_fn = __ptn_hist_prev;
	}

	ptn_k->key.ptn_id = (ptn_h->ptn_id)?(ptn_h->ptn_id):(i->filter.ptn_id);
	ptn_k->key.bin_width = (ptn_h->bin_width)?(ptn_h->bin_width)
						 :(i->filter.bin_width);
	ptn_k->key.time = (ptn_h->time)?(ptn_h->time)
				       :((fwd)?(i->filter.tv_begin.tv_sec)
					      :(i->filter.tv_end.tv_sec));
	ptn_hist_htobe(ptn_k);
	if (!fwd) {
		if (!ptn_k->key.ptn_id)
			ptn_k->key.ptn_id = -1;
		if (!ptn_k->key.bin_width)
			ptn_k->key.bin_width = -1;
		if (!ptn_k->key.time)
			ptn_k->key.time = -1;
	}
	hist_k->len = sizeof(ptn_k->key);

	rc = iter_fn(i->iter, key);
	if (rc)
		return rc;
	return step_fn(i);
}

static int
bs_ptn_hist_iter_find_fwd(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	return __bs_ptn_hist_iter_find(iter, 1, ptn_h);
}

static int
bs_ptn_hist_iter_find_rev(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	return __bs_ptn_hist_iter_find(iter, 0, ptn_h);
}

static int bs_ptn_hist_iter_first(bptn_hist_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bptn_hist_s hist = {
		.ptn_id = i->filter.ptn_id,
		.time = i->filter.tv_begin.tv_sec,
		.bin_width = i->filter.bin_width,
	};

	return bs_ptn_hist_iter_find_fwd(iter, &hist);
}

static int bs_ptn_hist_iter_last(bptn_hist_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bptn_hist_s hist = {
		.ptn_id = i->filter.ptn_id,
		.time = i->filter.tv_end.tv_sec,
		.bin_width = i->filter.bin_width,
	};

	return bs_ptn_hist_iter_find_rev(iter, &hist);
}

static bptn_hist_t bs_ptn_hist_iter_obj(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	ptn_hist_t ptn_o;
	sos_obj_ref_t ref;
	sos_key_t key_o;

	key_o = sos_iter_key(i->iter);
	if (!key_o)
		return NULL;
	ptn_o = (typeof(ptn_o))sos_key_value(key_o);
	ptn_h->ptn_id = be64toh(ptn_o->key.ptn_id);
	ptn_h->time = be32toh(ptn_o->key.time);
	ptn_h->bin_width =  be32toh(ptn_o->key.bin_width);
	sos_key_put(key_o);
	ref = sos_iter_ref(i->iter);
	ptn_h->msg_count = ref.idx_data.uint64_[1];
	return ptn_h;
}

static int bs_ptn_hist_iter_next(bptn_hist_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_next(i->iter);
	if (rc)
		return rc;

	return __ptn_hist_next(i);
}

static int bs_ptn_hist_iter_prev(bptn_hist_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_prev(i->iter);
	if (rc)
		return rc;

	return __ptn_hist_prev(i);
}

static bstore_iter_pos_t bs_comp_hist_iter_pos_get(bcomp_hist_iter_t iter)
{
	return __iter_pos_get((bsos_iter_t)iter);
}

static int bs_comp_hist_iter_pos_set(bcomp_hist_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;
	/* If the sos_iter already exists and is the correct type, use it */
	if (!i->iter || (i->iter_type != pos->iter_type))
		return ENOENT;
	return __iter_pos_set(i, pos);
}

static void bs_comp_hist_iter_pos_free(bcomp_hist_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bsos_iter_pos_s *pos = (typeof(pos))_pos;
	if ((iter->type != _pos->type) || (i->iter_type != pos->iter_type)) {
		assert(0 == "Iterator - Position type mismatch");
		return;
	}
	sos_iter_pos_put(i->iter, pos->sos_pos);
	free(pos);
}

bcomp_hist_iter_t bs_comp_hist_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t chi = calloc(1, sizeof(*chi));
	if (chi) {
		chi->bs = bs;
		chi->biter_type = BCOMP_HIST_ITER;
		chi->iter_type = COMP_HIST_ITER;
		chi->iter = sos_attr_iter_new(bss->comp_hist_key_attr);
		if (!chi->iter)
			goto err;
		sos_iter_flags_set(chi->iter, SOS_ITER_F_INF_LAST_DUP);
	}
	return (bcomp_hist_iter_t)chi;
 err:
	free(chi);
	return NULL;
}

static void bs_comp_hist_iter_free(bcomp_hist_iter_t i)
{
	bsos_iter_t chi = (bsos_iter_t)i;
	if (chi->iter)
		sos_iter_free(chi->iter);
	free(i);
}

/*
 * The index is ordered as follows:
 *   - bin width
 *   - unix timestamp
 *   - component id
 *   - ptn id
 */
static int __comp_hist_next(bsos_iter_t i)
{
	int rc = 0;
	struct comp_hist_s comp_s;
	sos_key_t key_o = sos_iter_key(i->iter);
	time_t start_time = i->filter.tv_begin.tv_sec;
	time_t end_time = i->filter.tv_end.tv_sec;
	for ( ; 0 == rc;
	      sos_key_put(key_o),
		      key_o = (0 == (rc = sos_iter_next(i->iter))?sos_iter_key(i->iter):NULL)) {

		comp_s = *(comp_hist_t)sos_key_value(key_o);
		comp_hist_betoh(&comp_s);

		if (i->filter.bin_width &&
				(i->filter.bin_width != comp_s.key.bin_width))
			/* Bin width is primary order, no more matches */
			break;

		if ((start_time && comp_s.key.time < start_time) ||
				(end_time && end_time < comp_s.key.time))
			/* Time doesn't match and is secondar, no more matches */
			break;
		if (i->filter.comp_id &&
				(i->filter.comp_id != comp_s.key.comp_id))
			/* comp id doesn't match */
			continue;

		if (i->filter.ptn_id && (i->filter.ptn_id != comp_s.key.ptn_id))
			continue;

		/* Everything matches, return it */
		sos_key_put(key_o);
		return 0;
	}
	if (key_o)
		sos_key_put(key_o);
	return ENOENT;
}

static int __comp_hist_prev(bsos_iter_t i)
{
	int rc = 0;
	struct comp_hist_s comp_s;
	sos_key_t key_o = sos_iter_key(i->iter);
	time_t start_time = i->filter.tv_begin.tv_sec;
	time_t end_time = i->filter.tv_end.tv_sec;
	for ( ; 0 == rc;
	      sos_key_put(key_o),
		      key_o = (0 == (rc = sos_iter_prev(i->iter))?sos_iter_key(i->iter):NULL)) {
		comp_s = *(comp_hist_t)sos_key_value(key_o);
		comp_hist_betoh(&comp_s);
		if (i->filter.bin_width &&
				(i->filter.bin_width != comp_s.key.bin_width))
			/* Bin width is primary order, no more matches */
			break;

		if ((start_time && comp_s.key.time < start_time) ||
				(end_time && end_time < comp_s.key.time))
			/* Time doesn't match and is secondar, no more matches */
			break;

		if (i->filter.comp_id &&
				(i->filter.comp_id != comp_s.key.comp_id))
			/* comp id doesn't match */
			continue;

		if (i->filter.ptn_id && (i->filter.ptn_id != comp_s.key.ptn_id))
			continue;

		/* Everything matches, return it */
		sos_key_put(key_o);
		return 0;
	}
	if (key_o)
		sos_key_put(key_o);
	return ENOENT;
}

static int
__bs_comp_hist_iter_find(bcomp_hist_iter_t iter, int fwd, bcomp_hist_t comp_h)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	SOS_KEY(key);
	ods_key_value_t hist_k = key->as.ptr;
	comp_hist_t comp_k = (comp_hist_t)hist_k->value;
	sos_obj_t hist_o;
	int (*iter_fn)(sos_iter_t, sos_key_t);
	int (*step_fn)(bsos_iter_t);
	int rc;

	if (fwd) {
		iter_fn = sos_iter_sup;
		step_fn = __comp_hist_next;
	} else {
		iter_fn = sos_iter_inf;
		step_fn = __comp_hist_prev;
	}

	comp_k->key.ptn_id = (comp_h->ptn_id)?(comp_h->ptn_id)
					     :(i->filter.ptn_id);
	comp_k->key.comp_id = (comp_h->comp_id)?(comp_h->comp_id)
					       :(i->filter.comp_id);
	comp_k->key.bin_width = (comp_h->bin_width)?(comp_h->bin_width)
						   :(i->filter.bin_width);
	comp_k->key.time = (comp_h->time)?(comp_h->time)
					 :((fwd)?(i->filter.tv_begin.tv_sec)
						:(i->filter.tv_end.tv_sec));
	comp_hist_htobe(comp_k);
	if (!fwd) {
		if (!comp_k->key.ptn_id)
			comp_k->key.ptn_id = -1;
		if (!comp_k->key.comp_id)
			comp_k->key.comp_id = -1;
		if (!comp_k->key.bin_width)
			comp_k->key.bin_width = -1;
		if (!comp_k->key.time)
			comp_k->key.time = -1;
	}
	hist_k->len = sizeof(comp_k->key);

	rc = iter_fn(i->iter, key);
	if (rc)
		return rc;
	return step_fn(i);
}

static int
bs_comp_hist_iter_find_fwd(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	return __bs_comp_hist_iter_find(iter, 1, comp_h);
}

static int
bs_comp_hist_iter_find_rev(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	return __bs_comp_hist_iter_find(iter, 0, comp_h);
}

static int bs_comp_hist_iter_first(bcomp_hist_iter_t iter)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bcomp_hist_s hist = {
		.bin_width = i->filter.bin_width,
		.comp_id = i->filter.comp_id,
		.ptn_id = i->filter.ptn_id,
		.time = i->filter.tv_begin.tv_sec,
	};
	return bs_comp_hist_iter_find_fwd(iter, &hist);
}

static int bs_comp_hist_iter_last(bcomp_hist_iter_t iter)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bcomp_hist_s hist = {
		.bin_width = i->filter.bin_width,
		.comp_id = i->filter.comp_id,
		.ptn_id = i->filter.ptn_id,
		.time = i->filter.tv_end.tv_sec,
	};
	return bs_comp_hist_iter_find_rev(iter, &hist);
}

static bcomp_hist_t bs_comp_hist_iter_obj(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc = 0;
	comp_hist_t comp_o;
	sos_obj_ref_t ref;
	sos_key_t key_o;

	key_o = sos_iter_key(i->iter);
	if (!key_o)
		return NULL;
	comp_o = (typeof(comp_o))sos_key_value(key_o);
	comp_h->comp_id = be64toh(comp_o->key.comp_id);
	comp_h->ptn_id = be64toh(comp_o->key.ptn_id);
	comp_h->bin_width = be32toh(comp_o->key.bin_width);
	comp_h->time = be32toh(comp_o->key.time);
	sos_key_put(key_o);
	ref = sos_iter_ref(i->iter);
	comp_h->msg_count = ref.idx_data.uint64_[1];
	return comp_h;
}

static int bs_comp_hist_iter_next(bcomp_hist_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_next(i->iter);
	if (rc)
		return rc;

	return __comp_hist_next(i);
}

static int bs_comp_hist_iter_prev(bcomp_hist_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_prev(i->iter);
	if (rc)
		return rc;

	return __comp_hist_prev(i);
}

static int bs_iter_filter_set(btkn_hist_iter_t iter,
					bstore_iter_filter_t filter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	i->filter = *filter;
	return 0;
}

static struct bstore_plugin_s plugin = {
	.open = bs_open,
	.close = bs_close,

	.tkn_type_get = bs_tkn_type_get,

	.tkn_add = bs_tkn_add,
	.tkn_add_with_id = bs_tkn_add_with_id,
	.tkn_find_by_id = bs_tkn_find_by_id,
	.tkn_find_by_name = bs_tkn_find_by_name,

	.tkn_iter_pos_get = bs_tkn_iter_pos_get,
	.tkn_iter_pos_set = bs_tkn_iter_pos_set,
	.tkn_iter_pos_free = bs_tkn_iter_pos_free,
	.tkn_iter_new = bs_tkn_iter_new,
	.tkn_iter_free = bs_tkn_iter_free,
	.tkn_iter_card = bs_tkn_iter_card,
	.tkn_iter_first = bs_tkn_iter_first,
	.tkn_iter_obj = bs_tkn_iter_obj,
	.tkn_iter_next = bs_tkn_iter_next,
	.tkn_iter_prev = bs_tkn_iter_prev,
	.tkn_iter_last = bs_tkn_iter_last,

	.msg_add = bs_msg_add,
	.msg_iter_pos_get = bs_msg_iter_pos_get,
	.msg_iter_pos_set = bs_msg_iter_pos_set,
	.msg_iter_pos_free = bs_msg_iter_pos_free,
	.msg_iter_new = bs_msg_iter_new,
	.msg_iter_free = bs_msg_iter_free,
	.msg_iter_card = bs_msg_iter_card,
	.msg_iter_find_fwd = bs_msg_iter_find_fwd,
	.msg_iter_find_rev = bs_msg_iter_find_rev,
	.msg_iter_obj = bs_msg_iter_obj,
	.msg_iter_first = bs_msg_iter_first,
	.msg_iter_next = bs_msg_iter_next,
	.msg_iter_prev = bs_msg_iter_prev,
	.msg_iter_last = bs_msg_iter_last,
	.msg_iter_filter_set = bs_msg_iter_filter_set,

	.ptn_add = bs_ptn_add,
	.ptn_find = bs_ptn_find,
	.ptn_find_by_ptnstr = bs_ptn_find_by_ptnstr,
	.ptn_iter_pos_get = bs_ptn_iter_pos_get,
	.ptn_iter_pos_set = bs_ptn_iter_pos_set,
	.ptn_iter_pos_free = bs_ptn_iter_pos_free,
	.ptn_iter_new = bs_ptn_iter_new,
	.ptn_iter_free = bs_ptn_iter_free,
	.ptn_iter_filter_set = bs_ptn_iter_filter_set,
	.ptn_iter_card = bs_ptn_iter_card,
	.ptn_iter_find_fwd = bs_ptn_iter_find_fwd,
	.ptn_iter_find_rev = bs_ptn_iter_find_rev,
	.ptn_iter_first = bs_ptn_iter_first,
	.ptn_iter_last = bs_ptn_iter_last,
	.ptn_iter_obj = bs_ptn_iter_obj,
	.ptn_iter_next = bs_ptn_iter_next,
	.ptn_iter_prev = bs_ptn_iter_prev,

	.ptn_tkn_iter_pos_get = bs_ptn_tkn_iter_pos_get,
	.ptn_tkn_iter_pos_set = bs_ptn_tkn_iter_pos_set,
	.ptn_tkn_iter_pos_free = bs_ptn_tkn_iter_pos_free,
	.ptn_tkn_iter_new = bs_ptn_tkn_iter_new,
	.ptn_tkn_iter_free = bs_ptn_tkn_iter_free,
	.ptn_tkn_iter_card = bs_ptn_tkn_iter_card,
	.ptn_tkn_iter_obj = bs_ptn_tkn_iter_obj,
	.ptn_tkn_iter_first = bs_ptn_tkn_iter_first,
	.ptn_tkn_iter_next = bs_ptn_tkn_iter_next,
	.ptn_tkn_iter_prev = bs_ptn_tkn_iter_prev,
	.ptn_tkn_iter_last = bs_ptn_tkn_iter_last,
	.ptn_tkn_iter_filter_set = bs_iter_filter_set,

	.tkn_hist_update = bs_tkn_hist_update,
	.tkn_hist_iter_pos_get = bs_tkn_hist_iter_pos_get,
	.tkn_hist_iter_pos_set = bs_tkn_hist_iter_pos_set,
	.tkn_hist_iter_pos_free = bs_tkn_hist_iter_pos_free,
	.tkn_hist_iter_new = bs_tkn_hist_iter_new,
	.tkn_hist_iter_free = bs_tkn_hist_iter_free,
	.tkn_hist_iter_find_fwd = bs_tkn_hist_iter_find_fwd,
	.tkn_hist_iter_find_rev = bs_tkn_hist_iter_find_rev,
	.tkn_hist_iter_obj = bs_tkn_hist_iter_obj,
	.tkn_hist_iter_next = bs_tkn_hist_iter_next,
	.tkn_hist_iter_prev = bs_tkn_hist_iter_prev,
	.tkn_hist_iter_first = bs_tkn_hist_iter_first,
	.tkn_hist_iter_last = bs_tkn_hist_iter_last,
	.tkn_hist_iter_filter_set = bs_iter_filter_set,

	.ptn_hist_update = bs_ptn_hist_update,
	.ptn_tkn_add = bs_ptn_tkn_add,
	.ptn_tkn_find = bs_ptn_tkn_find,

	.ptn_hist_iter_pos_get = bs_ptn_hist_iter_pos_get,
	.ptn_hist_iter_pos_set = bs_ptn_hist_iter_pos_set,
	.ptn_hist_iter_pos_free = bs_ptn_hist_iter_pos_free,
	.ptn_hist_iter_new = bs_ptn_hist_iter_new,
	.ptn_hist_iter_free = bs_ptn_hist_iter_free,
	.ptn_hist_iter_find_fwd = bs_ptn_hist_iter_find_fwd,
	.ptn_hist_iter_find_rev = bs_ptn_hist_iter_find_rev,
	.ptn_hist_iter_obj = bs_ptn_hist_iter_obj,
	.ptn_hist_iter_filter_set = bs_iter_filter_set,
	.ptn_hist_iter_first = bs_ptn_hist_iter_first,
	.ptn_hist_iter_next = bs_ptn_hist_iter_next,
	.ptn_hist_iter_prev = bs_ptn_hist_iter_prev,
	.ptn_hist_iter_last = bs_ptn_hist_iter_last,

	.comp_hist_iter_pos_get = bs_comp_hist_iter_pos_get,
	.comp_hist_iter_pos_set = bs_comp_hist_iter_pos_set,
	.comp_hist_iter_pos_free = bs_comp_hist_iter_pos_free,
	.comp_hist_iter_new = bs_comp_hist_iter_new,
	.comp_hist_iter_free = bs_comp_hist_iter_free,
	.comp_hist_iter_find_fwd = bs_comp_hist_iter_find_fwd,
	.comp_hist_iter_find_rev = bs_comp_hist_iter_find_rev,
	.comp_hist_iter_obj = bs_comp_hist_iter_obj,
	.comp_hist_iter_filter_set = bs_iter_filter_set,
	.comp_hist_iter_first = bs_comp_hist_iter_first,
	.comp_hist_iter_next = bs_comp_hist_iter_next,
	.comp_hist_iter_prev = bs_comp_hist_iter_prev,
	.comp_hist_iter_last = bs_comp_hist_iter_last,

};

bstore_plugin_t get_plugin(void)
{
	return &plugin;
}

