/* -*- c-basic-offset: 8 -*-
 */
#include "baler/bplugin.h"
#include "baler/boutput.h"
#include "baler/butils.h"
#include "baler/bstore.h"
#include "bout_store_ptn_tkn.h"
#include <limits.h>

static int plugin_start(struct bplugin *this)
{
	int rc;
	struct bout_store_ptn_tkn_plugin *mp = (typeof(mp))this;
	pthread_mutex_lock(&mp->lock);
	if (mp->bs) {
		rc = EINVAL;
		goto out;
	}
	mp->bs = bstore_open(bget_store_plugin(), bget_store_path(),
			     O_CREAT | O_RDWR, 0660);
	if (!mp->bs)
		rc = errno;
	else
		rc = 0;
 out:
	pthread_mutex_unlock(&mp->lock);
	return rc;
}

static int plugin_stop(struct bplugin *this)
{
	struct bout_store_ptn_tkn_plugin *mp = (typeof(mp))this;

	pthread_mutex_lock(&mp->lock);
	if (!mp->bs)
		/* Not running */
		goto out;
	bstore_close(mp->bs);
	mp->bs = NULL;
 out:
	pthread_mutex_unlock(&mp->lock);
	return 0;
}

static int plugin_config(struct bplugin *this, struct bpair_str_head *arg_head)
{
	return 0;
}

static int plugin_free(struct bplugin *this)
{
	struct bout_store_ptn_tkn_plugin *mp = (typeof(mp))this;
	if (mp->bs)
		plugin_stop(this);
	bplugin_free(this);
	return 0;
}

static int plugin_process_output(struct boutplugin *this, struct boutq_data *odata)
{
	struct bout_store_ptn_tkn_plugin *mp = (typeof(mp))this;
	bmsg_t msg = odata->msg;
	struct timeval *tv = &odata->tv;
	btkn_type_t type_id;
	int rc, pos;
	if (!mp->bs)
		return EINVAL;
	for (pos = 0; pos < msg->argc; pos++) {
		type_id = msg->argv[pos] & 0xff;
		if (type_id == BTKN_TYPE_TIMESTAMP)
			continue;
		rc = bstore_ptn_tkn_add(mp->bs, msg->ptn_id, pos, msg->argv[pos] >> 8);
		if (rc)
			goto err_0;
	}
	/*
	 * Add the hostname(comp_id) as a pseudo-token to those saved for the
	 * pattern. Hostname has the position -1
	 */
	rc = bstore_ptn_tkn_add(mp->bs, msg->ptn_id, -1, msg->comp_id);
	if (rc)
		goto err_0;
 err_0:
	return rc;
}

/* bout_store_ptn_tkn_plugin:boutplugin:bplugin */
struct bplugin *create_plugin_instance()
{
	struct bout_store_ptn_tkn_plugin *p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;
	p->base.base.name = strdup("bout_store_ptn_tkn");
	if (!p->base.base.name)
		return NULL;
	p->base.base.config = plugin_config;
	p->base.base.start = plugin_start;
	p->base.base.stop = plugin_stop;
	p->base.base.free = plugin_free;
	pthread_mutex_init(&p->lock, NULL);
	p->base.process_output = plugin_process_output;
	return (void*)p;
}

/**\}*/
