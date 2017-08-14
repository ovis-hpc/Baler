/* -*- c-basic-offset: 8 -*- */
#include <sys/syscall.h>
#include <assert.h>
#include "baler/bplugin.h"
#include "baler/boutput.h"
#include "baler/butils.h"
#include "baler/bstore.h"
#include "bout_store_hist.h"
#include "baler/btkn.h"
#include <limits.h>

#define MINUTES	60
#define HOURS	(MINUTES * 60)
#define DAYS	(HOURS * 24)
#define WEEKS	(DAYS * 7)

static uint32_t hist_bins[] = { MINUTES, HOURS, DAYS }; // , WEEKS };
time_t clamp_time_to_bin(time_t time_, uint32_t bin_width)
{
	return (time_ / bin_width) * bin_width;
}

static int plugin_start(struct bplugin *this)
{
	int rc;
	struct bout_store_hist_plugin *mp = (typeof(mp))this;
	pthread_mutex_lock(&mp->lock);
	if (mp->bs) {
		rc = EINVAL;
		goto out;
	}
	mp->bs = bstore_open(bget_store_plugin(),
			     bget_store_path(), O_CREAT | O_RDWR, 0660);
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
	struct bout_store_hist_plugin *mp = (typeof(mp))this;
	int i;
	printf("Stopping plugin!\n");
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

static long ent_id;
static long ent_count;

#define HIST_MAX_MSG 256
static int plugin_config(struct bplugin *this, struct bpair_str_head *arg_head)
{
	int i, rc;
	int blocking_mq = 0;
	struct bout_store_hist_plugin *mp = (typeof(mp))this;
	struct bpair_str *bpstr;
	bpstr = bpair_str_search(arg_head, "tkn", NULL);
	if (bpstr)
		mp->tkn_hist = strtoul(bpstr->s1, NULL, 0);
	bpstr = bpair_str_search(arg_head, "ptn", NULL);
	if (bpstr)
		mp->ptn_hist =  strtoul(bpstr->s1, NULL, 0);
	bpstr = bpair_str_search(arg_head, "ptn_tkn", NULL);
	if (bpstr)
		mp->ptn_tkn_hist =  strtoul(bpstr->s1, NULL, 0);
	return 0;
}

static int plugin_free(struct bplugin *this)
{
	struct bout_store_hist_plugin *mp = (typeof(mp))this;
	if (mp->bs)
		plugin_stop(this);
	bplugin_free(this);
	return 0;
}

static void do_tkn_hist(struct bout_store_hist_plugin *mp, bmsg_t msg, struct timeval *tv,
			int bin, int pos)
{
	bstore_tkn_hist_update(mp->bs, clamp_time_to_bin(tv->tv_sec, hist_bins[bin]),
			       hist_bins[bin], msg->argv[pos] >> 8);
}

static void do_ptn_tkn_hist(struct bout_store_hist_plugin *mp, bmsg_t msg, int pos)
{
	(void)bstore_ptn_tkn_add(mp->bs, msg->ptn_id, pos, msg->argv[pos] >> 8);
}

static void do_ptn_hist(struct bout_store_hist_plugin *mp, bmsg_t msg, struct timeval *tv, int bin)
{
	bstore_ptn_hist_update(mp->bs,
			       msg->ptn_id,
			       msg->comp_id,
			       clamp_time_to_bin(tv->tv_sec, hist_bins[bin]),
			       hist_bins[bin]);
}

static int plugin_process_output(struct boutplugin *this, struct boutq_data *odata)
{
	struct bout_store_hist_plugin *mp = (typeof(mp))this;
	bmsg_t msg = odata->msg;
	struct timeval *tv = &odata->tv;
	int rc = 0;
	int pos, bin;

	if (!mp->bs)
		return EINVAL;

	for (bin = 0; bin < sizeof(hist_bins) / sizeof(hist_bins[0]); bin++) {
		/* Pattern History */
		if (mp->ptn_hist)
			do_ptn_hist(mp, msg, tv, bin);
		if (!mp->tkn_hist)
			continue;
		for (pos = 0; pos < msg->argc; pos++) {
			/* Global Token History */
			do_tkn_hist(mp, msg, tv, bin, pos);
		}
	}
	/* Per-Pattern Token History */
	if (!mp->ptn_tkn_hist)
		return rc;
	for (pos = 0; pos < msg->argc; pos++) {
		if (btkn_id_is_wildcard(msg->argv[pos] & BTKN_TYPE_ID_MASK))
			do_ptn_tkn_hist(mp, msg, pos);
	}
	return rc;
}

/* bout_store_hist_plugin:boutplugin:bplugin */
struct bplugin *create_plugin_instance()
{
	struct bout_store_hist_plugin *p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;
	p->base.base.name = strdup("bout_store_hist");
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
