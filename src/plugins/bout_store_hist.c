/* -*- c-basic-offset: 8 -*- */
#include <sys/syscall.h>
#include <assert.h>
#include "baler/bplugin.h"
#include "baler/boutput.h"
#include "baler/butils.h"
#include "baler/bstore.h"
#include "baler/mq.h"
#include "bout_store_hist.h"
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
	for (i = 0; i < mp->thread_count; i++) {
		if (mp->threads[i]) {
			mq_finish(mp->mqs[i]);
			pthread_cancel(mp->threads[i]);
			pthread_join(mp->threads[i], NULL);
		}
	}
	if (!mp->bs)
		/* Not running */
		goto out;
	bstore_close(mp->bs);
	mp->bs = NULL;
 out:
	pthread_mutex_unlock(&mp->lock);
	return 0;
}

#define DEFAULT_Q_DEPTH 50
#define DEFAULT_THREAD_COUNT 19

static long ent_id;
static long ent_count;

static void *thread_fn(void *arg)
{
	mq_t mq = arg;
	mq_msg_t msg;
	int rc;
	while (msg = mq_get_cons_msg_wait(mq)) {
		rc = msg->msg_work_fn(mq, msg);
		mq_post_cons_msg(mq);
	}
	return NULL;
}

#define HIST_MAX_MSG 256
static int plugin_config(struct bplugin *this, struct bpair_str_head *arg_head)
{
	int i, rc;
	int blocking_mq = 0;
	struct bout_store_hist_plugin *mp = (typeof(mp))this;
	struct bpair_str *bpstr;
	char *thread_str = NULL;
	char *q_depth_str = NULL;
	bpstr = bpair_str_search(arg_head, "threads", NULL);
	if (bpstr) {
		thread_str = strdup(bpstr->s1);
		if (!thread_str)
			return ENOMEM;
	}
	bpstr = bpair_str_search(arg_head, "blocking_mq", NULL);
	if (bpstr) {
		blocking_mq = strtol(bpstr->s1, NULL, 0);
	}
	bpstr = bpair_str_search(arg_head, "q_depth", NULL);
	if (bpstr) {
		q_depth_str = strdup(bpstr->s1);
		if (!q_depth_str)
			return ENOMEM;
	}
	if (thread_str) {
		mp->thread_count = strtoul(thread_str, NULL, 0);
		free(thread_str);
	}
	if (!mp->thread_count || !thread_str)
		mp->thread_count = DEFAULT_THREAD_COUNT;
	mp->threads = calloc(mp->thread_count, sizeof(pthread_t));
	if (!mp->threads)
		return ENOMEM;
	mp->mqs = calloc(mp->thread_count, sizeof(struct mq_s *));
	if (!mp->mqs)
		return ENOMEM;
	if (q_depth_str) {
		mp->q_depth = strtoul(q_depth_str, NULL, 0);
		free(q_depth_str);
	}
	if (!mp->q_depth || !q_depth_str)
		mp->q_depth = DEFAULT_Q_DEPTH;
	for (i = 0; i < mp->thread_count; i++) {
		mp->mqs[i] = mq_new(mp->q_depth, HIST_MAX_MSG, blocking_mq);
		if (!mp->mqs[i])
			return ENOMEM;
		rc = pthread_create(&mp->threads[i], NULL,
				    thread_fn, mp->mqs[i]);
		if (rc)
			return errno;
	}
	mp->curr_nq = 0;

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
	if (mp->mqs) {
		int i;
		for (i = 0; i < mp->thread_count; i++)
			free(mp->mqs[i]);
		free(mp->mqs);
	}
	if (mp->threads)
		free(mp->threads);
	bplugin_free(this);
	return 0;
}

typedef struct tkn_hist_s {
	bstore_t bs;
	bptn_id_t tkn_id;
	time_t secs;
	time_t bin_width;
} *tkn_hist_t;
typedef struct ptn_hist_s {
	bstore_t bs;
	bptn_id_t ptn_id;
	bcomp_id_t comp_id;
	time_t secs;
	time_t bin_width;
} *ptn_hist_t;
typedef struct ptn_tkn_add_s {
	bstore_t bs;
	bptn_id_t ptn_id;
	uint64_t tkn_pos;
	btkn_id_t tkn_id;
} *ptn_tkn_add_t;
enum {
	WQE_TKN_HIST,
	WQE_PTN_HIST,
	WQE_PTN_TKN_HIST
};

typedef struct hist_msg_s {
	struct mq_msg_s hdr;
	union {
		struct tkn_hist_s tkn;
		struct ptn_hist_s ptn;
		struct ptn_tkn_add_s ptn_tkn;
	};
} *hist_msg_t;

static int ptn_hist_update(mq_t mq, mq_msg_t msg)
{
	assert(msg->msg_type == WQE_PTN_HIST);
	hist_msg_t hist_msg = (typeof(hist_msg))msg;
	return bstore_ptn_hist_update(hist_msg->ptn.bs,
				      hist_msg->ptn.ptn_id,
				      hist_msg->ptn.comp_id,
				      hist_msg->ptn.secs,
				      hist_msg->ptn.bin_width);
}

static int tkn_hist_update(mq_t mq, mq_msg_t msg)
{
	assert(msg->msg_type == WQE_TKN_HIST);
	hist_msg_t hist_msg = (typeof(hist_msg))msg;
	return bstore_tkn_hist_update(hist_msg->tkn.bs,
				      hist_msg->tkn.secs,
				      hist_msg->tkn.bin_width,
				      hist_msg->tkn.tkn_id);
}

static int ptn_tkn_hist_update(mq_t mq, mq_msg_t msg)
{
	assert(msg->msg_type == WQE_PTN_TKN_HIST);
	hist_msg_t hist_msg = (typeof(hist_msg))msg;
	return bstore_ptn_tkn_add(hist_msg->ptn_tkn.bs,
				  hist_msg->ptn_tkn.ptn_id,
				  hist_msg->ptn_tkn.tkn_pos,
				  hist_msg->ptn_tkn.tkn_id);
}

static void do_tkn_hist(struct bout_store_hist_plugin *mp, bmsg_t msg, struct timeval *tv,
			int bin, int pos)
{
	hist_msg_t hist_msg;
	mp->curr_nq = __sync_add_and_fetch(&mp->curr_nq, 1) % mp->thread_count;
	hist_msg = (hist_msg_t)mq_get_prod_msg_wait(mp->mqs[mp->curr_nq]);
	hist_msg->hdr.msg_type = WQE_TKN_HIST;
	hist_msg->hdr.msg_work_fn = tkn_hist_update;
	hist_msg->hdr.msg_size = sizeof(hist_msg);
	hist_msg->tkn.bs = mp->bs;
	hist_msg->tkn.secs = clamp_time_to_bin(tv->tv_sec, hist_bins[bin]);
	hist_msg->tkn.bin_width = hist_bins[bin];
	hist_msg->tkn.tkn_id = msg->argv[pos] >> 8;
	mq_post_prod_msg(mp->mqs[mp->curr_nq]);
}

static void do_ptn_tkn_hist(struct bout_store_hist_plugin *mp, bmsg_t msg, int pos)
{
	hist_msg_t hist_msg;
	mp->curr_nq = __sync_add_and_fetch(&mp->curr_nq, 1) % mp->thread_count;
	hist_msg = (hist_msg_t)mq_get_prod_msg_wait(mp->mqs[mp->curr_nq]);
	hist_msg->hdr.msg_type = WQE_PTN_TKN_HIST;
	hist_msg->hdr.msg_work_fn = ptn_tkn_hist_update;
	hist_msg->hdr.msg_size = sizeof(hist_msg);
	hist_msg->ptn_tkn.bs = mp->bs;
	hist_msg->ptn_tkn.ptn_id = msg->ptn_id;
	hist_msg->ptn_tkn.tkn_id = msg->argv[pos] >> 8;
	hist_msg->ptn_tkn.tkn_pos = pos;
	mq_post_prod_msg(mp->mqs[mp->curr_nq]);
}

static void do_ptn_hist(struct bout_store_hist_plugin *mp, bmsg_t msg, struct timeval *tv, int bin)
{
	hist_msg_t hist_msg;
	mp->curr_nq = __sync_add_and_fetch(&mp->curr_nq, 1) % mp->thread_count;
	hist_msg = (hist_msg_t)mq_get_prod_msg_wait(mp->mqs[mp->curr_nq]);
	hist_msg->hdr.msg_type = WQE_PTN_HIST;
	hist_msg->hdr.msg_work_fn = ptn_hist_update;
	hist_msg->hdr.msg_size = sizeof(hist_msg);
	hist_msg->ptn.bs = mp->bs;
	hist_msg->ptn.ptn_id = msg->ptn_id;
	hist_msg->ptn.comp_id = msg->comp_id;
	hist_msg->ptn.secs = clamp_time_to_bin(tv->tv_sec, hist_bins[bin]);
	hist_msg->ptn.bin_width = hist_bins[bin];
	mq_post_prod_msg(mp->mqs[mp->curr_nq]);
}

static int plugin_process_output(struct boutplugin *this, struct boutq_data *odata)
{
	struct bout_store_hist_plugin *mp = (typeof(mp))this;
	bmsg_t msg = odata->msg;
	struct timeval *tv = &odata->tv;
	int rc = 0;
	int pos, bin;
	hist_msg_t hist_msg;

	if (!mp->bs)
		return EINVAL;

	for (bin = 0; bin < sizeof(hist_bins) / sizeof(hist_bins[0]); bin++) {
		/* Pattern History */
		if (mp->ptn_hist)
			do_ptn_hist(mp, msg, tv, bin);
		for (pos = 0; pos < msg->argc; pos++) {
			/* Global Token History */
			if (mp->tkn_hist)
				do_tkn_hist(mp, msg, tv, bin, pos);
		}
	}
	/* Per-Pattern Token History */
	for (pos = 0; pos < msg->argc; pos++) {
		if (mp->ptn_tkn_hist == 1 || (mp->ptn_tkn_hist==2 &&
				btkn_type_is_wildcard(msg->argv[pos] & 0xFF)))
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
