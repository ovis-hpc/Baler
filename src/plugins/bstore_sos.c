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

#ifdef __be64
#pragma message "WARNING: __be64 is already defined!"
#else
#define __be64
#define __be32
#endif

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

#define H2BXT_IDX_ARGS "ORDER=5 SIZE=3"

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
			.idx_type = "HTBL",
			// .idx_type = "H2BXT",
			// .idx_args = H2BXT_IDX_ARGS,
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
			// .idx_type = "H2BXT",
			// .idx_args = H2BXT_IDX_ARGS,
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
			.idx_type = "H2BXT",
			.idx_args = H2BXT_IDX_ARGS,
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

struct sos_schema_template token_hist_schema = {
	.name = "TokenHist",
	.attrs = {
		{
			.name = "tkn_hist_key",
			.type = SOS_TYPE_STRUCT,
			.size = 16,
			.indexed = 1,
			.idx_type = "H2BXT",
			.idx_args = H2BXT_IDX_ARGS,
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

struct sos_schema_template pattern_hist_schema = {
	.name = "PatternHist",
	.attrs = {
		{
			.name = "ptn_hist_key",
			.type = SOS_TYPE_STRUCT,
			.size = 16,
			.indexed = 1,
			.idx_type = "H2BXT",
			.idx_args = H2BXT_IDX_ARGS,
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

struct sos_schema_template component_hist_schema = {
	.name = "ComponentHist",
	.attrs = {
		{
			.name = "comp_hist_key",
			.type = SOS_TYPE_STRUCT,
			.size = 24,
			.indexed = 1,
			.idx_type = "H2BXT",
			.idx_args = H2BXT_IDX_ARGS,
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
	for (type = BTKN_TYPE_FIRST+1; type < BTKN_TYPE_LAST; type++) {
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
	bptn_id_t ptn_id = bss->next_ptn_id;
	ptn_id = bss->next_ptn_id;
	bss->next_ptn_id = ptn_id + 1;
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

	assert((tkn->tkn_id < BTKN_TYPE_LAST)
	       || (tkn->tkn_id >= 0x100));
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
	pthread_mutex_lock(&bss->dict_lock);

	/* If the token is already added, return it's id */
	encode_tkn_key(text_key, tkn->tkn_str->cstr, tkn->tkn_str->blen);
	ctxt.bss = bss;
	ctxt.tkn = tkn;
	rc = sos_index_visit(sos_attr_index(bss->tkn_text_attr), text_key,
			     tkn_add_cb, &ctxt);

	sos_obj_put(ctxt.obj);
	pthread_mutex_unlock(&bss->dict_lock);
	return ctxt.tkn->tkn_id;
}

static int bs_tkn_add_with_id(bstore_t bs, btkn_t tkn)
{
	int rc;
	sos_obj_t tkn_obj;
	bstore_sos_t bss = (bstore_sos_t)bs;
	SOS_KEY(text_key);

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
	int iter_type;
	sos_iter_t iter;
	uint64_t arg;
	btkn_id_t tkn_id;
	bptn_id_t ptn_id;
	uint32_t bin_width;
	uint32_t start;
	uint64_t comp_id;
	bmsg_cmp_fn_t cmp_fn;
	void *cmp_ctxt;
} *bsos_iter_t;

struct bstore_iter_pos_s {
	int iter_type;
	struct sos_pos sos_pos;
};

static bstore_iter_pos_t __iter_pos(bsos_iter_t iter)
{
	int rc;
	struct bstore_iter_pos_s *pos;
	if (!iter->iter)
		return NULL;
	pos = malloc(sizeof *pos);
	if (!pos)
		return NULL;
	pos->iter_type = iter->iter_type;
	rc = sos_iter_pos(iter->iter, &pos->sos_pos);
	if (rc) {
		errno = rc;
		free(pos);
		pos = NULL;
	}
	return pos;
}

static int __iter_pos_set(bsos_iter_t iter, bstore_iter_pos_t _pos)
{
	struct bstore_iter_pos_s *pos = (typeof(pos))_pos;
	return sos_iter_set(iter->iter, (sos_pos_t)&pos->sos_pos);
}

static void bs_iter_pos_free(bstore_iter_t iter, bstore_iter_pos_t pos)
{
	free(pos);
}

static const char *bs_iter_pos_to_str(bstore_iter_t iter, bstore_iter_pos_t _pos)
{
	int i;
	struct bstore_iter_pos_s *pos = (typeof(pos))_pos;
	char *s, *pos_str = malloc(((sizeof(pos->sos_pos) + 1) << 1) + 1);
	if (!pos_str)
		return NULL;
	s = pos_str;
	sprintf(s, "%02hhX", (unsigned char)pos->iter_type);
	s += 2;
	for (i = 0; i < sizeof(pos->sos_pos); i++) {
		sprintf(s, "%02hhX", pos->sos_pos.data[i]);
		s += 2;
	}
	return pos_str;
}

static bstore_iter_pos_t bs_iter_pos_from_str(bstore_iter_t iter, const char *pos_str)
{
	int i, n;
	char iter_type;
	struct bstore_iter_pos_s *pos = malloc(sizeof *pos);
	if (!pos)
		return NULL;
	n = sscanf(pos_str, "%02hhX", &iter_type);
	if (n != 1)
		goto err;
	pos->iter_type = iter_type;
	pos_str += 2;
	for (i = 0; i < sizeof(pos->sos_pos.data); i++) {
		int n = sscanf(pos_str, "%02hhX", &pos->sos_pos.data[i]);
		if (n != 1)
			goto err;
		pos_str += 2;
	}
	return pos;
 err:
	free(pos);
	return NULL;
}

static bstore_iter_pos_t bs_tkn_iter_pos(btkn_iter_t iter)
{
	return __iter_pos((bsos_iter_t)iter);
}

static int bs_tkn_iter_pos_set(btkn_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bstore_iter_pos_s *pos = _pos;
	/* If the sos_iter already exists and is the correct type, use it */
	if (!i->iter || (i->iter_type != pos->iter_type))
		return ENOENT;
	return __iter_pos_set(i, pos);
}

static btkn_iter_t bs_tkn_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t ti = calloc(1, sizeof(*ti));
	if (ti) {
		ti->bs = bs;
		ti->iter_type = TKN_ITER;
		ti->iter = sos_attr_iter_new(bss->tkn_id_attr);
		if (!ti->iter)
			goto err;
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

static btkn_t bs_tkn_iter_first(btkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc = sos_iter_begin(i->iter);
	if (rc)
		return NULL;

	return __make_tkn(bss, sos_iter_obj(i->iter));
}

static btkn_t bs_tkn_iter_obj(btkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	return __make_tkn(bss, sos_iter_obj(i->iter));
}

static btkn_t bs_tkn_iter_next(btkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc = sos_iter_next(i->iter);
	if (rc)
		return NULL;

	return __make_tkn(bss, sos_iter_obj(i->iter));
}

static bstore_iter_pos_t bs_ptn_iter_pos(bptn_iter_t iter)
{
	return __iter_pos((bsos_iter_t)iter);
}

static int bs_ptn_iter_pos_set(bptn_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bstore_iter_pos_s *pos = _pos;
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
 set_pos:
	return __iter_pos_set(i, pos);
}

static bptn_iter_t bs_ptn_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t pi = calloc(1, sizeof(*pi));
	if (pi)
		pi->bs = bs;
	return (bptn_iter_t)pi;
}
static void bs_ptn_iter_free(bptn_iter_t i)
{
	bsos_iter_t pi = (bsos_iter_t)i;
	if (pi->iter)
		sos_iter_free(pi->iter);
	free(i);
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
	if (i && i->ptn_id > 0) {
		if (sptn->ptn_id != i->ptn_id)
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
	pthread_mutex_unlock(&bss->ptn_lock);
 cleanup_1:
	bstr_free(tmp_bstr);
 out:
	return rc;
}

static bptn_t bs_ptn_iter_find(bptn_iter_t iter, time_t start)
{
	SOS_KEY(time_key);
	ods_key_value_t kv = time_key->as.ptr;
	struct sos_timestamp_s *first_seen;
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc;
	i->start = start;
	if (i->iter)
		sos_iter_free(i->iter);
	if (start > 0) {
		i->iter_type = PTN_ITER_FIRST_SEEN;
		i->iter = sos_attr_iter_new(bss->first_seen_attr);
		if (!i->iter)
			goto err;
		first_seen = (struct sos_timestamp_s *)kv->value;
		first_seen->secs = start;
		first_seen->usecs = 0;
		kv->len = 8;
		rc = sos_iter_sup(i->iter, time_key);
	} else {
		i->iter_type = PTN_ITER_ID;
		i->iter = sos_attr_iter_new(bss->ptn_id_attr);
		if (!i->iter)
			goto err;
		rc = sos_iter_begin(i->iter);
	}
	if (rc)
		goto err;

	return __make_ptn(bss, i, sos_iter_obj(i->iter));
 err:
	return NULL;
}

static bptn_t bs_ptn_iter_first(bptn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc;
	i->ptn_id = 0;
	if (i->iter)
		sos_iter_free(i->iter);
	i->iter_type = PTN_ITER_ID;
	i->iter = sos_attr_iter_new(bss->ptn_id_attr);
	if (!i->iter)
		return NULL;
	rc = sos_iter_begin(i->iter);
	if (rc)
		return NULL;
	return __make_ptn(bss, i, sos_iter_obj(i->iter));
}

static bptn_t bs_ptn_iter_last(bptn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc;
	i->ptn_id = 0;
	if (i->iter)
		sos_iter_free(i->iter);
	i->iter_type = PTN_ITER_ID;
	i->iter = sos_attr_iter_new(bss->ptn_id_attr);
	if (!i->iter)
		return NULL;
	rc = sos_iter_end(i->iter);
	if (rc)
		return NULL;
	return __make_ptn(bss, i, sos_iter_obj(i->iter));
}

static bptn_t bs_ptn_iter_obj(bptn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	return __make_ptn(bss, i, sos_iter_obj(i->iter));
}

static bptn_t bs_ptn_iter_next(bptn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc = sos_iter_next(i->iter);
	if (rc)
		return NULL;

	return __make_ptn(bss, i, sos_iter_obj(i->iter));
}

static bptn_t bs_ptn_iter_prev(bptn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc = sos_iter_prev(i->iter);
	if (rc)
		return NULL;

	return __make_ptn(bss, i, sos_iter_obj(i->iter));
}

static bstore_iter_pos_t bs_ptn_tkn_iter_pos(bptn_tkn_iter_t iter)
{
	return __iter_pos((bsos_iter_t)iter);
}

static int bs_ptn_tkn_iter_pos_set(bptn_tkn_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bstore_iter_pos_s *pos = _pos;

	/* If the sos_iter already exists and is the correct type, use it */
	if (!i->iter || (i->iter_type != pos->iter_type))
		return ENOENT;

	return __iter_pos_set(i, pos);
}

static bptn_tkn_iter_t bs_ptn_tkn_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t pti = calloc(1, sizeof(*pti));
	if (pti) {
		pti->bs = bs;
		pti->iter_type = PTN_TKN_ITER;
		pti->iter = sos_attr_iter_new(bss->ptn_pos_tkn_key_attr);
		if (!pti->iter)
			goto err;
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

struct msg_iter_pos_s {
	int type;		/* ptn:time, comp:time, time:comp */
	struct sos_pos pos;
};

static bstore_iter_pos_t bs_msg_iter_pos(bmsg_iter_t iter)
{
	return __iter_pos((bsos_iter_t)iter);
}

static int bs_msg_iter_pos_set(bmsg_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bstore_iter_pos_s *pos = _pos;
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
 set_pos:
	return __iter_pos_set((bsos_iter_t)iter, pos);
}

static bmsg_iter_t bs_msg_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t mi = calloc(1, sizeof(*mi));
	if (mi)
		mi->bs = bs;
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

	if (!msg_obj)
		return NULL;

	smsg = sos_obj_ptr(msg_obj);
	tkn_ids = sos_value_init(&v_, msg_obj, bss->tkn_ids_attr);
	if (!tkn_ids)
		goto out;

	dmsg = malloc(sizeof(*dmsg) + (smsg->tkn_count * sizeof(uint64_t)));
	if (!dmsg)
		goto out;

	dmsg->ptn_id = be64toh(smsg->pt_key.ptn_id);
	uint64_t usecs = be64toh(smsg->pt_key.usecs);
	dmsg->timestamp.tv_sec = usecs / 1000000;
	dmsg->timestamp.tv_usec = usecs % 1000000;
	dmsg->comp_id = be64toh(smsg->ct_key.comp_id);
	dmsg->argc = smsg->tkn_count;
	decode_msg(dmsg, tkn_ids->data->array.data.byte_, smsg->tkn_count);

	sos_value_put(tkn_ids);
	sos_obj_put(msg_obj);
	return dmsg;
 out:
	sos_obj_put(msg_obj);
	return NULL;
}

static sos_obj_t __next_matching_msg(int rc, bsos_iter_t i, int forwards)
{
	msg_t msg;
	uint64_t msg_ptn, msg_time, msg_comp;
	sos_obj_t obj;

	for (;0 == rc; rc = (forwards ? sos_iter_next(i->iter) : sos_iter_prev(i->iter))) {
		obj = sos_iter_obj(i->iter);
		msg = sos_obj_ptr(obj);
		msg_ptn = be64toh(msg->pt_key.ptn_id);
		msg_time = be64toh(msg->pt_key.usecs);
		msg_comp = be64toh(msg->ct_key.comp_id);

		/* ptn_id specified and doesn't match, exit */
		if (i->ptn_id) {
			/* We're using the pt_msg_key index */
			if (i->ptn_id != msg_ptn)
				goto enoent;
			/* Skip component id's that don't match */
			if (i->comp_id && (i->comp_id != msg_comp)) {
				sos_obj_put(obj);
				continue;
			} else {
				/* matching object */
				break;
			}
		}
		if (i->comp_id && (i->comp_id != msg_comp)) {
			/* We're using the ct_msg_key index. If comp_id doesn't match,
			 * we've completed the iteration
			 */
			goto enoent;
		}

		/* We're using the tc_msg_key index, return the message */
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

	if (i->iter)
		sos_iter_free(i->iter);

	usecs = (uint64_t)start * 1000000;
	i->ptn_id = ptn_id;
	i->start = usecs;
	i->comp_id = comp_id;
	i->cmp_fn = cmp_fn;
	i->cmp_ctxt = ctxt;

	if (ptn_id) {
		i->iter_type = MSG_ITER_PTN_TIME;
		i->iter = sos_attr_iter_new(bss->pt_key_attr);
		if (!i->iter)
			goto err;
		pt_key = (struct pt_msg_key *)kv->value;
		pt_key->ptn_id = htobe64(ptn_id);
		pt_key->usecs = htobe64(usecs);
	} else if (comp_id) {
		i->iter_type = MSG_ITER_COMP_TIME;
		i->iter = sos_attr_iter_new(bss->ct_key_attr);
		if (!i->iter)
			goto err;
		ct_key = (struct ct_msg_key *)kv->value;
		ct_key->comp_id = htobe64(comp_id);
		ct_key->usecs = htobe64(usecs);
	} else {
		i->iter_type = MSG_ITER_TIME_COMP;
		i->iter = sos_attr_iter_new(bss->tc_key_attr);
		if (!i->iter)
			goto err;
		tc_key = (struct tc_msg_key *)kv->value;
		tc_key->usecs = htobe64(usecs);
		tc_key->comp_id = htobe64(comp_id);
	}
	kv->len = 16;

	rc = sos_iter_sup(i->iter, msg_key);
	obj = __next_matching_msg(rc, i, 1);
	if (obj)
		return __make_msg(bss, i, obj);
 err:
	return NULL;
}

static bmsg_t
bs_msg_iter_first(bmsg_iter_t iter)
{
	int rc;
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;

	i->ptn_id = 0;
	i->start = 0;
	i->comp_id = 0;
	i->cmp_fn = NULL;
	i->cmp_ctxt = 0;

	if (i->iter)
		sos_iter_free(i->iter);
	i->iter_type = MSG_ITER_TIME_COMP;
	i->iter = sos_attr_iter_new(bss->tc_key_attr);
	if (!i->iter)
		return NULL;
	rc = sos_iter_begin(i->iter);
	if (rc)
		return NULL;
	return __make_msg(bss, i, sos_iter_obj(i->iter));
}

static bmsg_t
bs_msg_iter_last(bmsg_iter_t iter)
{
	int rc;
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;

	i->ptn_id = 0;
	i->start = 0;
	i->comp_id = 0;
	i->cmp_fn = NULL;
	i->cmp_ctxt = 0;

	if (i->iter)
		sos_iter_free(i->iter);
	i->iter_type = MSG_ITER_TIME_COMP;
	i->iter = sos_attr_iter_new(bss->tc_key_attr);
	if (!i->iter)
		return NULL;
	rc = sos_iter_end(i->iter);
	if (rc)
		return NULL;
	return __make_msg(bss, i, sos_iter_obj(i->iter));
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

static bmsg_t bs_msg_iter_next(bmsg_iter_t iter)
{
	sos_obj_t obj;
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc;
	rc = sos_iter_next(i->iter);
	if (rc)
		return NULL;
	obj = __next_matching_msg(rc, i, 1);
	if (obj)
		return __make_msg(bss, i, obj);
	return NULL;
}

static bmsg_t bs_msg_iter_prev(bmsg_iter_t iter)
{
	sos_obj_t obj;
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	int rc;
	rc = sos_iter_prev(i->iter);
	if (rc)
		return NULL;
	obj = __next_matching_msg(rc, i, 0);
	if (obj)
		return __make_msg(bss, i, obj);
	return NULL;
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

static bptn_id_t bs_ptn_add(bstore_t bs, struct timeval *tv, bstr_t ptn)
{
	bptn_id_t ptn_id;
	ptn_t ptn_value;
	bstore_sos_t bss = (bstore_sos_t)bs;
	sos_obj_t ptn_obj;
	SOS_KEY_SZ(stack_key, 2048);
	sos_key_t ptn_key;
	int rc;

	if (ptn->blen <= 2048)
		ptn_key = stack_key;
	else
		ptn_key = sos_key_new(ptn->blen);
	/* If the pattern is already present, return it's ptn_id */
	size_t tkn_count = ptn->blen / sizeof(ptn->u64str[0]);
	size_t ptn_size = encode_ptn(ptn, tkn_count);
	sos_key_set(ptn_key, ptn->cstr, ptn_size);
	pthread_mutex_lock(&bss->ptn_lock);
	ptn_obj = sos_obj_find(bss->tkn_type_ids_attr, ptn_key);
	if (ptn_key != stack_key)
		sos_key_put(ptn_key);
	if (ptn_obj) {
		struct timeval last_seen;
		ptn_value = sos_obj_ptr(ptn_obj);
		last_seen.tv_sec = ptn_value->last_seen.secs;
		last_seen.tv_usec = ptn_value->last_seen.usecs;
		if (timercmp(&last_seen, tv, <)) {
			ptn_value->last_seen.secs = tv->tv_sec;
			ptn_value->last_seen.usecs = tv->tv_usec;
		}
		ptn_value->count ++;
		ptn_id = ptn_value->ptn_id;
		goto out;
	}

	/* Allocate and save this new pattern */
	ptn_obj = sos_obj_new(bss->pattern_schema);
	if (!ptn_obj)
		goto err_0;

	ptn_value = sos_obj_ptr(ptn_obj);
	if (!ptn_value)
		goto err_1;

	ptn_value->first_seen.secs = ptn_value->last_seen.secs = tv->tv_sec;
	ptn_value->first_seen.usecs = ptn_value->last_seen.usecs = tv->tv_usec;
	ptn_value->tkn_count = tkn_count;
	ptn_value->count = 1;

	sos_value_t v;
	struct sos_value_s v_;
	v = sos_array_new(&v_, bss->tkn_type_ids_attr, ptn_obj, ptn_size);
	if (!v)
		goto err_1;

	sos_value_memcpy(v, ptn->cstr, ptn_size);
	sos_value_put(v);
	ptn_id = ptn_value->ptn_id = allocate_ptn_id(bss);
	rc = sos_obj_index(ptn_obj);
	if (rc)
		goto err_1;
 out:
	sos_obj_put(ptn_obj);
	pthread_mutex_unlock(&bss->ptn_lock);
	return ptn_id;
 err_1:
	sos_obj_delete(ptn_obj);
	sos_obj_put(ptn_obj);
 err_0:
	pthread_mutex_unlock(&bss->ptn_lock);
	return 0;
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

	pthread_mutex_lock(&bss->ptn_tkn_lock);
	idx = sos_attr_index(bss->ptn_pos_tkn_key_attr);
	rc = sos_index_visit(idx, key, hist_cb, NULL);
	pthread_mutex_unlock(&bss->ptn_tkn_lock);
	return rc;
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

	ppt_k->key.ptn_id = htobe64(ptn_id);
	ppt_k->key.pos = htobe64(tkn_pos);
	ppt_k->key.tkn_id = htobe64(tkn_id);
	kv->len = sizeof(ppt_k->key);

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

	/* This code trashes the msg memory */
	msg = bmsg_dup(msg);
	if (!msg)
		return ENOMEM;

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
	pthread_mutex_unlock(&bss->msg_lock);
	bmsg_free(msg);
	return 0;
 err_1:
	sos_obj_delete(msg_obj);
	sos_obj_put(msg_obj);
 err_0:
	bmsg_free(msg);
	pthread_mutex_unlock(&bss->msg_lock);
	return rc;
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

	if ((tkn_pos_ != i->arg) || (ptn_id_ != i->ptn_id))
		goto out;

	tkn = bs_tkn_find_by_id(i->bs, tkn_id_);
	ref = sos_iter_ref(i->iter);
	tkn->tkn_count = ref.idx_data.uint64_[1];
	return tkn;

 out:
	return NULL;
}

static btkn_t bs_ptn_tkn_iter_find(bptn_tkn_iter_t iter,
				   bptn_id_t ptn_id, uint64_t tkn_pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	bstore_sos_t bss = (bstore_sos_t)i->bs;
	SOS_KEY(key);
	ods_key_value_t kv = key->as.ptr;
	ptn_pos_tkn_t ppt_k = (ptn_pos_tkn_t)kv->value;
	int rc;

	ppt_k->key.ptn_id = htobe64(ptn_id);
	ppt_k->key.pos = htobe64(tkn_pos);
	ppt_k->key.tkn_id = 0;
	kv->len = sizeof(ppt_k->key);

	i->ptn_id = ptn_id;
	i->arg = tkn_pos;

	rc = sos_iter_sup(i->iter, key);
	if (!rc)
		return make_ptn_tkn(i);
	return NULL;
}

static btkn_t bs_ptn_tkn_iter_obj(bptn_tkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	return make_ptn_tkn(i);
}

static btkn_t bs_ptn_tkn_iter_next(bptn_tkn_iter_t iter)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc = sos_iter_next(i->iter);
	if (!rc)
		return make_ptn_tkn(i);
	return NULL;
}

static bstore_iter_pos_t bs_tkn_hist_iter_pos(btkn_hist_iter_t iter)
{
	return __iter_pos((bsos_iter_t)iter);
}

static int bs_tkn_hist_iter_pos_set(btkn_hist_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bstore_iter_pos_s *pos = _pos;
	/* If the sos_iter already exists and is the correct type, use it */
	if (!i->iter || (i->iter_type != pos->iter_type))
		return ENOENT;
	return __iter_pos_set(i, pos);
}

btkn_hist_iter_t bs_tkn_hist_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t thi = calloc(1, sizeof(*thi));
	if (thi) {
		thi->bs = bs;
		thi->iter_type = TKN_HIST_ITER;
		thi->iter = sos_attr_iter_new(bss->tkn_hist_key_attr);
		if (!thi->iter)
			goto err;
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

int tkn_hist_match(bsos_iter_t i, tkn_hist_t tkn_o)
{
	if ((i->tkn_id && (i->tkn_id != tkn_o->key.tkn_id))
	    || (i->bin_width && (i->bin_width != tkn_o->key.bin_width))) {
		return 0;
	}
	return 1;
}

/*
 * Index order is:
 * - bin-width
 * - timestamp
 * - token id
 */
static btkn_hist_t tkn_hist_next(bsos_iter_t i, btkn_hist_t tkn_h)
{
	int rc = 0;
	tkn_hist_t tkn_o;
	sos_key_t key_o = sos_iter_key(i->iter);
	time_t hist_time;
	time_t start_time = be32toh(i->start);
	sos_obj_ref_t ref;
	for ( ; 0 == rc;
	      sos_key_put(key_o),
		      key_o = (0 == (rc = sos_iter_next(i->iter))?sos_iter_key(i->iter):NULL)) {

		tkn_o = (tkn_hist_t)sos_key_value(key_o);
		if (i->bin_width && (i->bin_width != tkn_o->key.bin_width))
			/* Bin width doesn't match, no more matches */
			break;

		hist_time = be32toh(tkn_o->key.time);
		if (start_time && start_time > hist_time)
			/* Time doesn't match, no more matches */
			break;

		if (i->tkn_id && (i->tkn_id != tkn_o->key.tkn_id))
			/* tkn id doesn't match, keep looking */
			continue;

		/* Everything matches, return it */
		tkn_h->tkn_id = be64toh(tkn_o->key.tkn_id);
		tkn_h->bin_width = be32toh(tkn_o->key.bin_width);
		tkn_h->time = be32toh(tkn_o->key.time);
		ref = sos_iter_ref(i->iter);
		tkn_h->tkn_count = ref.idx_data.uint64_[1];
		return tkn_h;
	}
	if (key_o)
		sos_key_put(key_o);
	return NULL;
}

static btkn_hist_t tkn_hist_prev(bsos_iter_t i, btkn_hist_t tkn_h)
{
	int rc = 0;
	tkn_hist_t tkn_o;
	sos_key_t key_o = sos_iter_key(i->iter);
	time_t hist_time;
	time_t start_time = be32toh(i->start);
	sos_obj_ref_t ref;
	for ( ; 0 == rc;
	      sos_key_put(key_o),
		      key_o = (0 == (rc = sos_iter_prev(i->iter))?sos_iter_key(i->iter):NULL)) {

		tkn_o = (tkn_hist_t)sos_key_value(key_o);
		if (i->bin_width && (i->bin_width != tkn_o->key.bin_width))
			/* Bin width doesn't match, no more matches */
			break;

		hist_time = be32toh(tkn_o->key.time);
		if (start_time && start_time < hist_time)
			/* Time doesn't match, no more matches */
			break;

		if (i->tkn_id && (i->tkn_id != tkn_o->key.tkn_id))
			/* tkn id doesn't match, keep looking */
			continue;

		/* Everything matches, return it */
		tkn_h->tkn_id = be64toh(tkn_o->key.tkn_id);
		tkn_h->bin_width = be32toh(tkn_o->key.bin_width);
		tkn_h->time = be32toh(tkn_o->key.time);
		ref = sos_iter_ref(i->iter);
		tkn_h->tkn_count = ref.idx_data.uint64_[1];
		return tkn_h;
	}
	if (key_o)
		sos_key_put(key_o);
	return NULL;
}

static btkn_hist_t
bs_tkn_hist_iter_find(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	SOS_KEY(key);
	ods_key_value_t hist_k = key->as.ptr;
	tkn_hist_t tkn_k = (tkn_hist_t)hist_k->value;
	sos_obj_t hist_o;
	int rc;

	i->tkn_id = htobe64(tkn_h->tkn_id);
	i->bin_width = htobe32(tkn_h->bin_width);
	i->start = htobe32(clamp_time_to_bin(tkn_h->time, tkn_h->bin_width));

	tkn_k->key.tkn_id = i->tkn_id;
	tkn_k->key.bin_width = i->bin_width;
	tkn_k->key.time = i->start;
	hist_k->len = sizeof(tkn_k->key);

	rc = sos_iter_sup(i->iter, key);
	if (rc)
		return NULL;

	return tkn_hist_next(i, tkn_h);
}
static btkn_hist_t
bs_tkn_hist_iter_last(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	SOS_KEY(key);
	ods_key_value_t hist_k = key->as.ptr;
	tkn_hist_t tkn_k = (tkn_hist_t)hist_k->value;
	sos_obj_t hist_o;
	int rc;

	i->tkn_id = htobe64(tkn_h->tkn_id);
	i->bin_width = htobe32(tkn_h->bin_width);
	i->start = htobe32(clamp_time_to_bin(tkn_h->time, tkn_h->bin_width));

	tkn_k->key.tkn_id = (i->tkn_id)?(i->tkn_id):(-1);
	tkn_k->key.bin_width = i->bin_width;
	tkn_k->key.time = (i->start)?(i->start):(-1);
	hist_k->len = sizeof(tkn_k->key);

	rc = sos_iter_inf(i->iter, key);
	if (rc)
		return NULL;

	return tkn_hist_prev(i, tkn_h);
}

static btkn_hist_t bs_tkn_hist_iter_first(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_begin(i->iter);
	if (rc)
		return NULL;

	return tkn_hist_next(i, tkn_h);
}

static btkn_hist_t bs_tkn_hist_iter_obj(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	return tkn_hist_next(i, tkn_h);
}

static btkn_hist_t bs_tkn_hist_iter_next(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_next(i->iter);
	if (rc)
		return NULL;

	return tkn_hist_next(i, tkn_h);
}

static btkn_hist_t bs_tkn_hist_iter_prev(btkn_hist_iter_t iter, btkn_hist_t tkn_h)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_prev(i->iter);
	if (rc)
		return NULL;

	return tkn_hist_prev(i, tkn_h);
}

static bstore_iter_pos_t bs_ptn_hist_iter_pos(bptn_hist_iter_t iter)
{
	return __iter_pos((bsos_iter_t)iter);
}

static int bs_ptn_hist_iter_pos_set(bptn_hist_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bstore_iter_pos_s *pos = _pos;
	/* If the sos_iter already exists and is the correct type, use it */
	if (!i->iter || (i->iter_type != pos->iter_type))
		return ENOENT;
	return __iter_pos_set(i, pos);
}

bptn_hist_iter_t bs_ptn_hist_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t phi = calloc(1, sizeof(*phi));
	if (phi) {
		phi->bs = bs;
		phi->iter_type = PTN_HIST_ITER;
		phi->iter = sos_attr_iter_new(bss->ptn_hist_key_attr);
		if (!phi->iter)
			goto err;
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
	if ((i->ptn_id && (i->ptn_id != ptn_o->key.ptn_id))
	    || (i->bin_width && (i->bin_width != ptn_o->key.bin_width))) {
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
static bptn_hist_t ptn_hist_next(bsos_iter_t i, bptn_hist_t ptn_h)
{
	int rc = 0;
	ptn_hist_t ptn_o;
	sos_key_t key_o = sos_iter_key(i->iter);
	sos_obj_ref_t ref;
	time_t hist_time;
	time_t start_time = be32toh(i->start);
	for ( ; 0 == rc;
	      sos_key_put(key_o),
		      key_o = (0 == (rc = sos_iter_next(i->iter))?sos_iter_key(i->iter):NULL)) {

		ptn_o = (typeof(ptn_o))sos_key_value(key_o);
		if (i->bin_width && (i->bin_width != ptn_o->key.bin_width))
			/* Bin width doesn't match, no more matches */
			break;

		hist_time = be32toh(ptn_o->key.time);
		if (start_time && start_time > hist_time)
			/* Time doesn't match, no more matches */
			break;

		if (i->ptn_id && (i->ptn_id != ptn_o->key.ptn_id))
			/* ptn id doesn't match, skip mismatch */
			continue;

		/* Everything matches, return it */
		ptn_h->ptn_id = be64toh(ptn_o->key.ptn_id);
		ptn_h->bin_width = be32toh(ptn_o->key.bin_width);
		ptn_h->time = be32toh(ptn_o->key.time);
		sos_key_put(key_o);
		ref = sos_iter_ref(i->iter);
		ptn_h->msg_count = ref.idx_data.uint64_[1];
		return ptn_h;
	}
	if (key_o)
		sos_key_put(key_o);
	return NULL;
}

static bptn_hist_t ptn_hist_prev(bsos_iter_t i, bptn_hist_t ptn_h)
{
	int rc = 0;
	ptn_hist_t ptn_o;
	sos_key_t key_o = sos_iter_key(i->iter);
	sos_obj_ref_t ref;
	time_t hist_time;
	time_t start_time = be32toh(i->start);
	for ( ; 0 == rc;
	      sos_key_put(key_o),
		      key_o = (0 == (rc = sos_iter_prev(i->iter))?sos_iter_key(i->iter):NULL)) {

		ptn_o = (typeof(ptn_o))sos_key_value(key_o);
		if (i->bin_width && (i->bin_width != ptn_o->key.bin_width))
			/* Bin width doesn't match, no more matches */
			break;

		hist_time = be32toh(ptn_o->key.time);
		if (start_time && start_time < hist_time)
			/* Time doesn't match, no more matches */
			break;

		if (i->ptn_id && (i->ptn_id != ptn_o->key.ptn_id))
			/* ptn id doesn't match, skip mismatch */
			continue;

		/* Everything matches, return it */
		ptn_h->ptn_id = be64toh(ptn_o->key.ptn_id);
		ptn_h->bin_width = be32toh(ptn_o->key.bin_width);
		ptn_h->time = be32toh(ptn_o->key.time);
		sos_key_put(key_o);
		ref = sos_iter_ref(i->iter);
		ptn_h->msg_count = ref.idx_data.uint64_[1];
		return ptn_h;
	}
	if (key_o)
		sos_key_put(key_o);
	return NULL;
}

static bptn_hist_t
bs_ptn_hist_iter_find(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	SOS_KEY(key);
	ods_key_value_t hist_k = key->as.ptr;
	ptn_hist_t ptn_k = (ptn_hist_t)hist_k->value;
	sos_obj_t hist_o;
	int rc;

	i->ptn_id = htobe64(ptn_h->ptn_id);
	i->bin_width = htobe32(ptn_h->bin_width);
	i->start = htobe32(clamp_time_to_bin(ptn_h->time, ptn_h->bin_width));

	ptn_k->key.ptn_id = i->ptn_id;
	ptn_k->key.bin_width = i->bin_width;
	ptn_k->key.time = i->start;
	hist_k->len = sizeof(ptn_k->key);

	rc = sos_iter_sup(i->iter, key);
	if (rc)
		return NULL;

	return ptn_hist_next(i, ptn_h);
}

static bptn_hist_t bs_ptn_hist_iter_first(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	ptn_hist_t ptn_o;
	sos_obj_t hist_o;
	int rc;

	i->ptn_id = 0;
	i->bin_width = ptn_h->bin_width;
	i->start = 0;

	rc = sos_iter_begin(i->iter);
	if (rc)
		return NULL;

	return ptn_hist_next(i, ptn_h);
}

static bptn_hist_t bs_ptn_hist_iter_last(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	SOS_KEY(key);
	ods_key_value_t hist_k = key->as.ptr;
	ptn_hist_t ptn_k = (ptn_hist_t)hist_k->value;
	sos_obj_t hist_o;
	int rc;

	i->ptn_id = htobe64(ptn_h->ptn_id);
	i->bin_width = htobe32(ptn_h->bin_width);
	i->start = htobe32(ptn_h->time);

	ptn_k->key.ptn_id = i->ptn_id;
	ptn_k->key.bin_width = i->bin_width;
	ptn_k->key.time = (i->start)?(i->start):(-1);
	hist_k->len = sizeof(ptn_k->key);

	rc = sos_iter_inf(i->iter, key);
	if (rc)
		return NULL;

	return ptn_hist_prev(i, ptn_h);
}

static bptn_hist_t bs_ptn_hist_iter_obj(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	return ptn_hist_next(i, ptn_h);
}

static bptn_hist_t bs_ptn_hist_iter_next(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_next(i->iter);
	if (rc)
		return NULL;

	return ptn_hist_next(i, ptn_h);
}

static bptn_hist_t bs_ptn_hist_iter_prev(bptn_hist_iter_t iter, bptn_hist_t ptn_h)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_prev(i->iter);
	if (rc)
		return NULL;

	return ptn_hist_prev(i, ptn_h);
}

static bstore_iter_pos_t bs_comp_hist_iter_pos(bcomp_hist_iter_t iter)
{
	return __iter_pos((bsos_iter_t)iter);
}

static int bs_comp_hist_iter_pos_set(bcomp_hist_iter_t iter, bstore_iter_pos_t _pos)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	struct bstore_iter_pos_s *pos = _pos;
	/* If the sos_iter already exists and is the correct type, use it */
	if (!i->iter || (i->iter_type != pos->iter_type))
		return ENOENT;
	return __iter_pos_set(i, pos);
}

bcomp_hist_iter_t bs_comp_hist_iter_new(bstore_t bs)
{
	bstore_sos_t bss = (bstore_sos_t)bs;
	bsos_iter_t chi = calloc(1, sizeof(*chi));
	if (chi) {
		chi->bs = bs;
		chi->iter_type = COMP_HIST_ITER;
		chi->iter = sos_attr_iter_new(bss->comp_hist_key_attr);
		if (!chi->iter)
			goto err;
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
static bcomp_hist_t comp_hist_next(bsos_iter_t i, bcomp_hist_t comp_h)
{
	int rc = 0;
	comp_hist_t comp_o;
	sos_key_t key_o = sos_iter_key(i->iter);
	sos_obj_ref_t ref;
	time_t hist_time;
	time_t start_time = be32toh(i->start);
	for ( ; 0 == rc;
	      sos_key_put(key_o),
		      key_o = (0 == (rc = sos_iter_next(i->iter))?sos_iter_key(i->iter):NULL)) {
		comp_o = (typeof(comp_o))sos_key_value(key_o);
		if (i->bin_width && (i->bin_width != comp_o->key.bin_width))
			/* Bin width is primary order, no more matches */
			break;

		hist_time = be32toh(comp_o->key.time);
		if (start_time && start_time > hist_time)
			/* Time doesn't match and is secondar, no more matches */
			break;

		if (i->comp_id && (i->comp_id != comp_o->key.comp_id))
			/* comp id doesn't match */
			continue;

		if (i->ptn_id && (i->ptn_id != comp_o->key.ptn_id))
			continue;

		/* Everything matches, return it */
		comp_h->comp_id = be64toh(comp_o->key.comp_id);
		comp_h->ptn_id = be64toh(comp_o->key.ptn_id);
		comp_h->bin_width = be32toh(comp_o->key.bin_width);
		comp_h->time = be32toh(comp_o->key.time);
		sos_key_put(key_o);
		ref = sos_iter_ref(i->iter);
		comp_h->msg_count = ref.idx_data.uint64_[1];
		return comp_h;
	}
	if (key_o)
		sos_key_put(key_o);
	return NULL;
}

static bcomp_hist_t comp_hist_prev(bsos_iter_t i, bcomp_hist_t comp_h)
{
	int rc = 0;
	comp_hist_t comp_o;
	sos_key_t key_o = sos_iter_key(i->iter);
	sos_obj_ref_t ref;
	time_t hist_time;
	time_t start_time = be32toh(i->start);
	for ( ; 0 == rc;
	      sos_key_put(key_o),
		      key_o = (0 == (rc = sos_iter_prev(i->iter))?sos_iter_key(i->iter):NULL)) {
		comp_o = (typeof(comp_o))sos_key_value(key_o);
		if (i->bin_width && (i->bin_width != comp_o->key.bin_width))
			/* Bin width is primary order, no more matches */
			break;

		hist_time = be32toh(comp_o->key.time);
		if (start_time && start_time <hist_time)
			/* Time doesn't match and is secondary, no more matches */
			break;

		if (i->comp_id && (i->comp_id != comp_o->key.comp_id))
			/* comp id doesn't match */
			continue;

		if (i->ptn_id && (i->ptn_id != comp_o->key.ptn_id))
			continue;

		/* Everything matches, return it */
		comp_h->comp_id = be64toh(comp_o->key.comp_id);
		comp_h->ptn_id = be64toh(comp_o->key.ptn_id);
		comp_h->bin_width = be32toh(comp_o->key.bin_width);
		comp_h->time = be32toh(comp_o->key.time);
		sos_key_put(key_o);
		ref = sos_iter_ref(i->iter);
		comp_h->msg_count = ref.idx_data.uint64_[1];
		return comp_h;
	}
	if (key_o)
		sos_key_put(key_o);
	return NULL;
}

static bcomp_hist_t
bs_comp_hist_iter_find(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	SOS_KEY(key);
	ods_key_value_t hist_k = key->as.ptr;
	comp_hist_t comp_k = (comp_hist_t)hist_k->value;
	int rc;

	i->comp_id = htobe64(comp_h->comp_id);
	i->ptn_id = htobe64(comp_h->ptn_id);
	i->start = htobe32(clamp_time_to_bin(comp_h->time, comp_h->bin_width));
	i->bin_width = htobe32(comp_h->bin_width);

	comp_k->key.comp_id = i->comp_id;
	comp_k->key.ptn_id = i->ptn_id;
	comp_k->key.bin_width = i->bin_width;
	comp_k->key.time = i->start;
	hist_k->len = sizeof(comp_k->key);

	rc = sos_iter_sup(i->iter, key);
	if (rc)
		return NULL;

	return comp_hist_next(i, comp_h);
}

static bcomp_hist_t bs_comp_hist_iter_first(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	comp_hist_t comp_o;
	int rc;

	rc = sos_iter_begin(i->iter);
	if (rc)
		return NULL;

	return comp_hist_next(i, comp_h);
}

static bcomp_hist_t bs_comp_hist_iter_last(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	bstore_sos_t bss = (bstore_sos_t)iter->bs;
	bsos_iter_t i = (bsos_iter_t)iter;
	SOS_KEY(key);
	ods_key_value_t hist_k = key->as.ptr;
	comp_hist_t comp_k = (comp_hist_t)hist_k->value;
	int rc;

	i->comp_id = htobe64(comp_h->comp_id);
	i->ptn_id = htobe64(comp_h->ptn_id);
	i->start = htobe32(comp_h->time);
	i->bin_width = htobe32(comp_h->bin_width);

	comp_k->key.comp_id = (i->comp_id)?(i->comp_id):(-1);
	comp_k->key.ptn_id = (i->ptn_id)?(i->ptn_id):(-1);
	comp_k->key.bin_width = i->bin_width;
	comp_k->key.time = (i->start)?(i->start):(-1);
	hist_k->len = sizeof(comp_k->key);

	rc = sos_iter_inf(i->iter, key);
	if (rc)
		return NULL;

	return comp_hist_prev(i, comp_h);
}

static bcomp_hist_t bs_comp_hist_iter_obj(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	return comp_hist_next((bsos_iter_t)iter, comp_h);
}

static bcomp_hist_t bs_comp_hist_iter_next(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_next(i->iter);
	if (rc)
		return NULL;

	return comp_hist_next(i, comp_h);
}

static bcomp_hist_t bs_comp_hist_iter_prev(bcomp_hist_iter_t iter, bcomp_hist_t comp_h)
{
	bsos_iter_t i = (bsos_iter_t)iter;
	int rc;

	rc = sos_iter_prev(i->iter);
	if (rc)
		return NULL;

	return comp_hist_prev(i, comp_h);
}

static struct bstore_plugin_s plugin = {
	.open = bs_open,
	.close = bs_close,

	.tkn_type_get = bs_tkn_type_get,

	.tkn_add = bs_tkn_add,
	.tkn_add_with_id = bs_tkn_add_with_id,
	.tkn_find_by_id = bs_tkn_find_by_id,
	.tkn_find_by_name = bs_tkn_find_by_name,

	.tkn_iter_pos = bs_tkn_iter_pos,
	.tkn_iter_pos_set = bs_tkn_iter_pos_set,
	.tkn_iter_new = bs_tkn_iter_new,
	.tkn_iter_free = bs_tkn_iter_free,
	.tkn_iter_card = bs_tkn_iter_card,
	.tkn_iter_first = bs_tkn_iter_first,
	.tkn_iter_obj = bs_tkn_iter_obj,
	.tkn_iter_next = bs_tkn_iter_next,
	// .tkn_iter_prev = bs_tkn_iter_prev,

	.msg_add = bs_msg_add,
	.msg_iter_pos = bs_msg_iter_pos,
	.msg_iter_pos_set = bs_msg_iter_pos_set,
	.msg_iter_new = bs_msg_iter_new,
	.msg_iter_free = bs_msg_iter_free,
	.msg_iter_card = bs_msg_iter_card,
	.msg_iter_find = bs_msg_iter_find,
	.msg_iter_first = bs_msg_iter_first,
	.msg_iter_last = bs_msg_iter_last,
	.msg_iter_obj = bs_msg_iter_obj,
	.msg_iter_next = bs_msg_iter_next,
	.msg_iter_prev = bs_msg_iter_prev,

	.ptn_add = bs_ptn_add,
	.ptn_find = bs_ptn_find,
	.ptn_find_by_ptnstr = bs_ptn_find_by_ptnstr,
	.ptn_iter_pos = bs_ptn_iter_pos,
	.ptn_iter_pos_set = bs_ptn_iter_pos_set,
	.ptn_iter_new = bs_ptn_iter_new,
	.ptn_iter_free = bs_ptn_iter_free,
	.ptn_iter_card = bs_ptn_iter_card,
	.ptn_iter_find = bs_ptn_iter_find,
	.ptn_iter_first = bs_ptn_iter_first,
	.ptn_iter_last = bs_ptn_iter_last,
	.ptn_iter_obj = bs_ptn_iter_obj,
	.ptn_iter_next = bs_ptn_iter_next,
	.ptn_iter_prev = bs_ptn_iter_prev,

	.ptn_tkn_iter_pos = bs_ptn_tkn_iter_pos,
	.ptn_tkn_iter_pos_set = bs_ptn_tkn_iter_pos_set,
	.ptn_tkn_iter_new = bs_ptn_tkn_iter_new,
	.ptn_tkn_iter_free = bs_ptn_tkn_iter_free,
	.ptn_tkn_iter_card = bs_ptn_tkn_iter_card,
	.ptn_tkn_iter_find = bs_ptn_tkn_iter_find,
	.ptn_tkn_iter_obj = bs_ptn_tkn_iter_obj,
	.ptn_tkn_iter_next = bs_ptn_tkn_iter_next,
	// .ptn_tkn_iter_prev = bs_ptn_tkn_iter_prev,

	.tkn_hist_update = bs_tkn_hist_update,
	.tkn_hist_iter_pos = bs_tkn_hist_iter_pos,
	.tkn_hist_iter_pos_set = bs_tkn_hist_iter_pos_set,
	.tkn_hist_iter_new = bs_tkn_hist_iter_new,
	.tkn_hist_iter_free = bs_tkn_hist_iter_free,
	.tkn_hist_iter_find = bs_tkn_hist_iter_find,
	.tkn_hist_iter_obj = bs_tkn_hist_iter_obj,
	.tkn_hist_iter_next = bs_tkn_hist_iter_next,
	.tkn_hist_iter_prev = bs_tkn_hist_iter_prev,
	.tkn_hist_iter_first = bs_tkn_hist_iter_find,
	.tkn_hist_iter_last = bs_tkn_hist_iter_last,

	.ptn_hist_update = bs_ptn_hist_update,
	.ptn_tkn_add = bs_ptn_tkn_add,
	.ptn_tkn_find = bs_ptn_tkn_find,
	.ptn_hist_iter_pos = bs_ptn_hist_iter_pos,
	.ptn_hist_iter_pos_set = bs_ptn_hist_iter_pos_set,
	.ptn_hist_iter_new = bs_ptn_hist_iter_new,
	.ptn_hist_iter_free = bs_ptn_hist_iter_free,
	.ptn_hist_iter_find = bs_ptn_hist_iter_find,
	.ptn_hist_iter_obj = bs_ptn_hist_iter_obj,
	.ptn_hist_iter_next = bs_ptn_hist_iter_next,
	.ptn_hist_iter_prev = bs_ptn_hist_iter_prev,
	.ptn_hist_iter_first = bs_ptn_hist_iter_find,
	.ptn_hist_iter_last = bs_ptn_hist_iter_last,

	.comp_hist_iter_pos = bs_comp_hist_iter_pos,
	.comp_hist_iter_pos_set = bs_comp_hist_iter_pos_set,
	.comp_hist_iter_new = bs_comp_hist_iter_new,
	.comp_hist_iter_free = bs_comp_hist_iter_free,
	.comp_hist_iter_find = bs_comp_hist_iter_find,
	.comp_hist_iter_obj = bs_comp_hist_iter_obj,
	.comp_hist_iter_next = bs_comp_hist_iter_next,
	.comp_hist_iter_prev = bs_comp_hist_iter_prev,
	.comp_hist_iter_first = bs_comp_hist_iter_find,
	.comp_hist_iter_last = bs_comp_hist_iter_last,

	.iter_pos_to_str = bs_iter_pos_to_str,
	.iter_pos_from_str = bs_iter_pos_from_str,
	.iter_pos_free = bs_iter_pos_free,
};

bstore_plugin_t init_store(void)
{
	return &plugin;
}

