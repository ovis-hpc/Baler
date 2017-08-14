/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2013-2016 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2013-2016 Sandia Corporation. All rights reserved.
 *
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
 * \file balerd.c
 * \author Narate Taerat (narate@ogc.us)
 * \date Mar 19, 2013
 */

/**
 * \mainpage Baler - a log processing system.
 *
 * Baler is a set of software for log processing. <tt>balerd</tt> (\ref balerd)
 * listens for forwarded logs from various sources (one of which is rsyslogd),
 * then it extracts a pattern and stores the message (in a reduced form -- see
 * \ref balerd for more information). <tt>balerd</tt> also supports distributed
 * log processing -- having more than one <tt>balerd</tt> working together to
 * process large number of logs (e.g. from different node/rack).
 *
 * \c bquery (\ref bquery) is a program to query patterns, messages and other
 * information from the data processed by \c balerd. The query can be performed
 * live, i.e. \c bquery can query the data while \c balerd is running. Please
 * see \ref bquery page for more information about querying.
 *
 * \c bhttpd (\ref bhttpd) is an HTTP server providing Baler data access similar
 * to \c bquery. Please note that \c bhttpd serves only the back-end data (in
 * JSON format). The front-end elements are not included.
 *
 * For the front-end GUI, Baler comes with a set of basic GUI widgets and query
 * library (to communicate with \c bhttpd) implemented in JavaScript. Please see
 * baler/src/bhttpd/html/ in the source tree for more information.
 *
 * \par links
 * - \ref balerd
 * - \ref bquery
 * - \ref bhttpd
 * - \ref bassoc
 */

/**
 * \page balerd Baler daemon
 *
 * \section synopsis SYNOPSIS
 * \b balerd [\b OPTIONS]
 *
 * \section description DESCRIPTION
 *
 * \b balerd (Baler Daemon) is the core program that process input messages
 * (prepared by various input plugins -- see more in \ref binput). The process
 * starts by an input plugin prepares an input entry and post it to the \b
 * balerd's input queue. In an input entry, a message is decomposed roughly into
 * three fields: timestamp, host or component name, and a list tokens composing
 * the message.
 *
 * \b balerd process an input entry by transforming the host name and tokens
 * into numbers (IDs). The message at this stage will be described as a sequence
 * of token IDs instead of a sequence of tokens. The mapping (token_ID <-->
 * token) is stored in \b balerd internal store.
 *
 * Next, \b balerd extracts a pattern out of a message by preserving static
 * tokens in the message and replacing the variable tokens by a special token
 * '*'. Right now, the heuristic to determine a static token is to check whether
 * it is an English word--if so, it is a static token. The extracted pattern is
 * checked against or inserted into a pattern mapping (pattern_ID <--> pattern)
 * to obtain a pattern_ID. The pattern mapping is also stored inside \b balerd's
 * internal store.  Then, the message is reduced into the form of <pattern_ID,
 * token_ID0, token_ID1, ...>, where token_ID#'s are the corresponding
 * token_ID's in the variable positions.
 *
 * The processed (reduced) message is then forwarded to Baler Output Plugins
 * (see \ref boutput) for further processing and message storage.
 *
 * \b balerd input and output plugins can be configured via Baler Configuration
 * file. Please see \ref configuration section below.
 *
 * \section options OPTIONS
 *
 * \par -l LOG_PATH
 * Log file (default: None, and log to stdout)
 *
 * \par -s STORE_PATH
 * Path to a baler store (default: ./store)
 *
 * \par -C CONFIG_FILE
 * Path to the configuration (Baler commands) file. This is optional as users
 * may use ocmd to configure baler.
 *
 * \par -F
 * Run in foreground mode (default: daemon mode)
 *
 * \par -z OCM_PORT
 * Specifying a port for receiving OCM connection and configuration (default:
 * 20005).
 *
 * \par -I NUMBER
 * Specify the number of input worker threads (default: 1).
 *
 * \par -O NUMBER
 * Specify the number of output worker threads (default: 1).
 *
 * \par -?
 * Display help message.
 *
 * \section configuration CONFIGURATION
 *
 * Baler configuration file (OPTION \b -C) contains a sequence of \b balerd
 * config commands to configure \b balerd. The available commands are documented
 * as follows.
 *
 * \subsection config_command CONFIGURATION COMMANDS
 *
 * \par tokens type=(ENG|HOST) path=PATH
 * Load ENG or HOST tokens from PATH. Please see \ref tkn_file_format below for
 * more information.
 *
 * \par plugin name=PLUGIN_NAME [PLUGIN-SPECIFIC-OPTIONS]
 * Load the plugin \b PLUGIN_NAME and configure the plugin with \b
 * PLUGIN-SPECIFIC-OPTIONS. The specified plugin can either be input or output
 * plugins (or both ... if the developer wants to). Conventionally, the input
 * plugin names start with 'bin_' and the output plugin names start with
 * 'bout_'. It is advisable to load output plugins BEFORE the input plugins to
 * prevent lost output data as \b balerd could finish processing some of the
 * input before the output plugins finish loading. Please see each plugin
 * documentation for its specific options (e.g. \b bin_rsyslog_tcp.config(5)).
 *
 * \par # comment
 * The '#' comment at the beginning of each line is supported. However, the
 * in-line trailing '#' comment is not supported. For example:
 * \par
 * \code
 * # This is a good comment.
 * tokens type=ENG path=my_dict # This is a bad comment.
 * \endcode
 *
 * \section conf_example CONFIGURATION_EXAMPLE
 * \par
 * \code
 * tokens type=ENG path=/path/to/word.list
 * tokens type=HOST path=/path/to/host.list
 *
 * # Image output with 3600 seconds (1 hour) pixel granularity.
 * plugin name=bout_sos_img delta_ts=3600
 *
 * # Another image output with 60 seconds (1 minute) pixel granularity.
 * plugin name=bout_sos_img delta_ts=60
 *
 * # Message output
 * plugin name=bout_sos_msg
 *
 * # Input plugin for rsyslog, don't forget to configure rsyslog in each
 * # node to forward messages to balerd host, port 11111.
 * plugin name=bin_rsyslog_tcp port=11111
 *
 * # Input processing plugin for metric data. The metric data will be converted
 * # into message-based event data (metricX is in range [A, B]) to feed to
 * # balerd.
 * plugin name=bin_metric port=22222 bin_file=METRIC_BIN_FILE
 * \endcode
 *
 * For the detail of each plugin configuration, please see the respective plugin
 * configuration page (e.g. \b bin_rsyslog_tcp.config(5))
 *
 *
 * \section tkn_file_format HOST AND TOKEN FILE FORMAT
 *
 * Each line of the file contains a token with an optional ID assignment:
 *   \b TOKEN [<b>ID</b>]
 *
 * Token aliasing can be ndone by assign those tokens the same token ID.
 *
 * \subsection tkn_file TOKEN FILE
 * The following example of a token file with aliasing:
 * \par
 * \code
 * ABC 128
 * DEF 128
 * XYZ
 * \endcode
 *
 * Please note that token IDs less than 128 are reserved for \b balerd internal
 * use. In the above example, if ABC or DEF appeared in messages, they will be
 * recognized as the same token. If the ID is not present, \b balerd
 * automatically assigns the max_ID + 1.
 *
 * The output of \b balerd will always produce the first alias, because \b
 * balerd stores messages as a sequence of token IDs which get translated back
 * to strings at the output.
 *
 * \subsection hst_file HOST FILE
 *
 * The following example of a host file with aliasing:
 * \par
 * \code
 * nid00000 0
 * login0 0
 * nid00001 1
 * login1 1
 * \endcode
 *
 * Host IDs starts from 0 to make things more convenient for users. \b balerd
 * will convert that into the real token ID space (starts from 128) internally.
 *
 * From the above example, the host field of the messages generated from
 * nid00000 and login0 will be recognized and stored as 0. Similar to token
 * file, if the ID is not present, \b balerd will automatically assign the
 * max_ID+1.
 *
 * Please note that on the output side, the first alias will be printed.
 *
 */

/**
 * \defgroup balerd_dev Baler Daemon Development Documentation
 * \{
 * \brief Baler daemon implementation.
 */
#include <stdio.h>
#include <pthread.h>
#include <limits.h>
#include <ctype.h>
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <assert.h>
#include <semaphore.h>

#ifdef ENABLE_OCM
#include "ocm/ocm.h"
ocm_t ocm; /**< ocm handle */
char ocm_key[512]; /**< $HOSTNAME/balerd */
uint16_t ocm_port = 20005;
int ocm_cb(struct ocm_event *e);
#endif

#include "bcommon.h"
#include "btypes.h"
#include "butils.h"
#include "bmapper.h"
#include "binput_private.h"
#include "boutput.h"
#include "btkn.h"
#include "bptn.h"
#include "bwqueue.h"
#include "bstore.h"

/***** Definitions *****/
typedef enum bmap_idx_enum {
	BMAP_IDX_TKN,
	BMAP_IDX_HST,
	BMAP_IDX_PTN,
} bmap_idx_e;

typedef enum bzmsg_type_enum {
	BZMSG_TYPE_FIRST=0,
	BZMSG_ID_REQ = BZMSG_TYPE_FIRST,
	BZMSG_ID_REP,
	BZMSG_BSTR_REQ,
	BZMSG_BSTR_REP,
	BZMSG_INSERT_REQ,
	BZMSG_INSERT_REP,
	BZMSG_TYPE_LAST,
} bzmsg_type_e;

struct bzmsg {
	uint32_t type;
	void *ctxt;
	void *ctxt_bstr;
	int rc;
	uint32_t mapidx;
	int tkn_idx;

	uint32_t id;
	struct btkn_attr attr;
	struct bstr bstr;
};

struct bzmsg *bzmsg_alloc(size_t bstr_len)
{
	return malloc(sizeof(struct bzmsg) + bstr_len);
}

/***** Command line arguments ****/
#define BALER_OPT_STR "FC:l:s:S:v:I:O:Q:V?"
#ifdef ENABLE_OCM
const char *optstring = BALER_OPT_STR "z:";
#else
const char *optstring = BALER_OPT_STR;
#endif
const char *config_path = NULL;
const char *log_path = NULL;

void display_help_msg()
{
	const char *help_msg =
"Usage: balerd [options]\n"
"\n"
"Options: \n"
"	-l <path>	Log file (log to stdout by default)\n"
"	-s <path>	Store path (default: ./store)\n"
"	-S <name>	Storage backend plugin name.\n"
"	-C <path>	Configuration (Baler commands) file\n"
"	-F		Foreground mode (default: daemon mode)\n"
#ifdef ENABLE_OCM
"	-z <port>	ocm port for balerd (default: 20005).\n"
#endif
"	-v <LEVEL>	Set verbosity level (DEBUG, INFO, WARN, ERROR).\n"
"			The default value is WARN.\n"
"	-I <number>	The number of input queue worker.\n"
"	-O <number>	The number of output queue worker.\n"
"	-Q <number>	The queue depth (applied to input and output queues).\n"
"	-V		Print the verion and exit.\n"
"	-?		Show help message\n"
"\n"
"For more information see balerd(3) manpage.\n"
"\n";
	printf("%s\n", help_msg);
}

/********** Configuration Variables **********/
/**
 * \defgroup bconf_vars Configuration Variables
 * \{
 */
int binqwkrN = 1; /**< Input Worker Thread Number */
int boutqwkrN = 1; /**< Output Worker Thread Number */
int qdepth = 1024; /**< Input/Output queue depth */
int is_foreground = 0; /**< Run as foreground? */

char *m_host = NULL;
char *sm_xprt = "sock";
struct timeval reconnect_interval = {.tv_sec = 2};

/**\}*/

/********** Configuration Commands **********/
char* str_to_lower(char *s)
{
	while (s) {
		*s = tolower(*s);
		s++;
	}
	return s;
}

/* define cfg commands here.
 * an extra '_' infront of LIST is to prevent name collision with possible
 * command 'list' */
#define BCFG_CMD__LIST(PREFIX, CMD) \
	CMD(PREFIX, PLUGIN), \
	CMD(PREFIX, TOKENS)

/* automatically generated enum */
enum BCFG_CMD {
	BCFG_CMD__LIST(BCFG_CMD_, BENUM),
	BCFG_CMD_LAST
};

/* automatically generated command strings */
#define BCFG_CMD_STR(X) #X,
const char *bcfg_str[] = {
	BCFG_CMD__LIST(, BENUM_STR)
};

enum BCFG_CMD bcfg_cmd_str2enum(const char *s)
{
	return bget_str_idx(bcfg_str, BCFG_CMD_LAST, s);
}

/********** Global Variable Section **********/

/**
 * Input queue workers
 */
pthread_t *binqwkr;

/**
 * Head of the ::bconfig_list.
 */
LIST_HEAD(bconfig_head, bconfig_list);

/**
 * List of plugin configurations.
 */
struct bconfig_list {
	char *command; /**< Configuration command */
	struct bpair_str_head arg_head_s; /**< Argument list head */
	LIST_ENTRY(bconfig_list) link; /**< The link to next/prev item */
};

/**
 * The input plugin configuration list head.
 */
struct bconfig_head bipconf_head_s = {NULL};

/**
 * The output plugin configuration list head.
 */
struct bconfig_head bopconf_head_s = {NULL};

/**
 * Plugin instance list head.
 */
LIST_HEAD(bplugin_head, bplugin);

/**
 * Input plugin instance head.
 */
struct bplugin_head bip_head_s = {NULL};

/**
 * Output plugin instance head.
 */
struct bplugin_head bop_head_s = {NULL};

/**
 * Output queue workers
 */
pthread_t *boutqwkr;
struct bwq *boutq; /* array of boutq, one queue per worker */
int *boutq_busy_count; /* queue busy count */

/**
 * Context for Output Worker.
 */
struct bout_wkr_ctxt {
	int worker_id; /**< Worker ID */
};

bstore_t bstore = NULL;

/*********************************************/

const char *bzmsg_type_str(bzmsg_type_e e)
{
	static const char *_str[] = {
		[BZMSG_ID_REQ]      =  "BZMSG_ID_REQ",
		[BZMSG_ID_REP]      =  "BZMSG_ID_REP",
		[BZMSG_BSTR_REQ]    =  "BZMSG_BSTR_REQ",
		[BZMSG_BSTR_REP]    =  "BZMSG_BSTR_REP",
		[BZMSG_INSERT_REQ]  =  "BZMSG_INSERT_REQ",
		[BZMSG_INSERT_REP]  =  "BZMSG_INSERT_REP",
	};

	if (BZMSG_TYPE_FIRST <= e && e < BZMSG_TYPE_LAST)
		return _str[e];
	return "UNKNOWN";
}

size_t bzmsg_len(struct bzmsg *m)
{
	size_t len = sizeof(*m);
	switch (m->type) {
	case BZMSG_ID_REQ:
	case BZMSG_BSTR_REP:
	case BZMSG_INSERT_REQ:
		len += m->bstr.blen;
		break;
	}
	return len;
}

void hton_bzmsg(struct bzmsg *m)
{
	switch (m->type) {
	case BZMSG_BSTR_REP:
	case BZMSG_INSERT_REQ:
		m->attr.type = htobe32(m->attr.type);
	case BZMSG_ID_REQ:
		m->bstr.blen = htobe32(m->bstr.blen);
		break;
	case BZMSG_ID_REP:
	case BZMSG_INSERT_REP:
		m->attr.type = htobe32(m->attr.type);
	case BZMSG_BSTR_REQ:
		m->id = htobe32(m->id);
		break;
	}
	m->mapidx = htobe32(m->mapidx);
	m->rc = htobe32(m->rc);
	m->type = htobe32(m->type);
}

void ntoh_bzmsg(struct bzmsg *m)
{
	m->type = be32toh(m->type);
	m->rc = be32toh(m->rc);
	m->mapidx = be32toh(m->mapidx);
	switch (m->type) {
	case BZMSG_BSTR_REP:
	case BZMSG_INSERT_REQ:
		m->attr.type = be32toh(m->attr.type);
	case BZMSG_ID_REQ:
		m->bstr.blen = be32toh(m->bstr.blen);
		break;
	case BZMSG_ID_REP:
	case BZMSG_INSERT_REP:
		m->attr.type = be32toh(m->attr.type);
	case BZMSG_BSTR_REQ:
		m->id = be32toh(m->id);
		break;
	}
}

struct bwq *get_least_busy_boutq()
{
	struct bwq *q;
	int i, mini;
	mini = 0;
	for (i = 1; i < boutqwkrN; i++) {
		if (boutq_busy_count[i] < boutq_busy_count[mini])
			mini = i;
	}
	boutq_busy_count[mini]++;
	return &boutq[mini];
}

void* binqwkr_routine(void *arg);
void* boutqwkr_routine(void *arg);

void bconfig_list_free(struct bconfig_list *bl) {
	struct bpair_str *bp;
	if (bl->command)
		free(bl->command);
	while ((bp = LIST_FIRST(&bl->arg_head_s))) {
		LIST_REMOVE(bp, link);
		bpair_str_free(bp);
	}
	free(bl);
}

static inline
bzmsg_type_e bzmsg_type_inverse(bzmsg_type_e type)
{
	return (type ^ 1);
}

/**
 * Baler Daemon Initialization.
 */
void initialize_daemon()
{
	int i;
	int rc;
	/* Daemonize? */
	if (!is_foreground) {
		binfo("Daemonizing...");
		if (daemon(1, 1) == -1) {
			berror("daemon");
			exit(-1);
		}
		binfo("Daemonized");
	}
	umask(0);

	/* Input/Output Work Queue */
	binq = bwq_alloci(qdepth);
	if (!binq) {
		berror("(binq) bwq_alloci");
		exit(-1);
	}

	/* Open store plugin */
	binfo("Opening Plugin Store.");
	bstore = bstore_open(bget_store_plugin(), bget_store_path(),
			     O_CREAT | O_RDWR, 0660);
	if (!bstore) {
		berror("bstore_open");
		berr("Cannot open plugin '%s' store '%s'.\n",
		     bget_store_plugin(), bget_store_path());
		exit(-1);
	}

	/* Input worker threads */
	binqwkr = malloc(sizeof(*binqwkr)*binqwkrN);
	if (!binqwkr) {
		berror("malloc for binqwkr");
		exit(-1);
	}
	for (i=0; i<binqwkrN; i++) {
		if ((rc = pthread_create(binqwkr+i, NULL, binqwkr_routine, NULL)) != 0) {
			berr("pthread_create error code: %d\n", rc);
			exit(-1);
		}
	}

	/* Output worker threads */
	boutqwkr = malloc(sizeof(*boutqwkr)*boutqwkrN);
	if (!boutqwkr) {
		berror("malloc for boutqwkr");
		exit(-1);
	}
	boutq_busy_count = calloc(boutqwkrN, sizeof(int));
	if (!boutq_busy_count) {
		berror("calloc for boutqwkr_busy_count");
		exit(-1);
	}
	boutq = malloc(sizeof(*boutq) * boutqwkrN);
	if (!boutq) {
		berror("malloc for boutq");
		exit(-1);
	}
	struct bout_wkr_ctxt *octxt;
	for (i=0; i<boutqwkrN; i++) {
		bwq_init(&boutq[i], qdepth);
		octxt = calloc(1, sizeof(*octxt));
		if (!octxt) {
			berror("calloc for octxt");
			exit(-1);
		}
		octxt->worker_id = i;
		if ((rc = pthread_create(boutqwkr+i, NULL, boutqwkr_routine,
						octxt)) != 0) {
			berr("pthread_create error, code: %d\n", rc);
			exit(-1);
		}
	}

	/* OCM */
#ifdef ENABLE_OCM
	ocm = ocm_create("sock", ocm_port, ocm_cb, __blog);
	if (!ocm) {
		berr("cannot create ocm: error %d\n", errno);
		exit(-1);
	}
	rc = gethostname(ocm_key, 512);
	if (rc) {
		berr("cannot get hostname, error %d: %m\n", errno);
		exit(-1);
	}
	sprintf(ocm_key + strlen(ocm_key), "/%s", "balerd");
	ocm_register(ocm, ocm_key, ocm_cb);
	rc = ocm_enable(ocm);
	if (rc) {
		berr("ocm_enable failed, rc: %d", rc);
		berr("Please check if port %d is occupied.", ocm_port);
		exit(-1);
	}
#endif
	binfo("Baler Initialization Complete.");
}

/**
 * Load a single plugin and put it into the given plugin instance list.
 * \param pcl The load plugin configuration.
 * \param inst_head The head of the plugin instance list.
 * \return 0 on success.
 * \return Error code on error.
 */
int load_plugin(struct bconfig_list *pcl, struct bplugin_head *inst_head)
{
	int rc = 0;
	char plibso[PATH_MAX];
	struct bpair_str *bname = bpair_str_search(&pcl->arg_head_s,
			"name", NULL);
	if (!bname) {
		berr("Cannot load plugin without argument 'name', "
				"command: %s", pcl->command);
		rc = EINVAL;
		goto out;
	}
	sprintf(plibso, "lib%s.so", bname->s1);
	void *h = dlopen(plibso, RTLD_NOW);
	if (!h) {
		rc = ELIBACC;
		berr("dlopen: %s\n", dlerror());
		goto out;
	}
	struct bplugin* (*pcreate)();
	dlerror(); /* Clear current dlerror */
	*(void**) (&pcreate) = dlsym(h, "create_plugin_instance");
	char *err = dlerror();
	if (err) {
		rc = ELIBBAD;
		berr("dlsym error: %s\n", err);
		goto out;
	}
	struct bplugin *p = pcreate();
	if (!p) {
		rc = errno;
		berr("Cannot create plugin %s\n", bname->s1);
		goto out;
	}
	LIST_INSERT_HEAD(inst_head, p, link);
	/* Configure the plugin. */
	if ((rc = p->config(p, &pcl->arg_head_s))) {
		berr("Config error, code: %d\n", rc);
		goto out;
	}

	/* And start the plugin. Plugin should not block this though. */
	if ((rc = p->start(p))) {
		berr("Plugin %s start error, code: %d\n", bname->s1,
				rc);
		goto out;
	}

out:
	return rc;
}

/**
 * A simple macro to skip the delimiters in \c d.
 * \param x A pointer to the string.
 * \param d A pointer to the string containing delimiters.
 */
#define SKIP_DELIMS(x, d) while (*(x) && strchr((d), *(x))) {(x)++;}

#define WHITE_SPACES " \t"

/**
 * Get the first token from \c *s. The returned string is newly created, and \c
 * *s will point to the next token. On error, \c *s will not be changed and the
 * function returns NULL.
 * \param[in,out] s \c *s is the string.
 * \param delims The delimiters.
 * \return NULL on error.
 * \return A pointer to the extracted token. Caller is responsible for freeing
 * 	it.
 */
char* get_token(const char **s, char* delims)
{
	const char *str = *s;
	while (*str && !strchr(delims, *str)) {
		str++;
	}
	int len = str - *s;
	char *tok = malloc(len + 1);
	if (!tok)
		return NULL;
	memcpy(tok, *s, len);
	tok[len] = 0;
	*s = str;
	return tok;
}

/**
 * Parse the configuration string \c cstr.
 * \param cstr The configuration string (e.g. "rsyslog port=9999").
 * \return NULL on error.
 * \return The pointer to ::bconfig_list, containing the parsed
 * 	information.
 */
struct bconfig_list* parse_config_str(const char *cstr)
{
	struct bconfig_list *l = calloc(1, sizeof(*l));
	if (!l)
		goto err0;
	const char *s = cstr;
	SKIP_DELIMS(s, WHITE_SPACES);

	/* The first token is the name of the plugin. */
	l->command = get_token(&s, WHITE_SPACES);
	if (!l->command) {
		errno = EINVAL;
		goto err1;
	}
	SKIP_DELIMS(s, WHITE_SPACES);

	/* The rest are <key>=<value> configuration arguments. */
	char *value;
	char *key;
	struct bpair_str *pstr;
	struct bpair_str tail; /* dummy tail */
	LIST_INSERT_HEAD(&l->arg_head_s, &tail, link);
	while (*s && (key = get_token(&s, "="WHITE_SPACES))) {
		SKIP_DELIMS(s, "="WHITE_SPACES);
		value = get_token(&s, WHITE_SPACES);
		SKIP_DELIMS(s, WHITE_SPACES);
		if (!value) {
			errno = EINVAL;
			goto err2;
		}
		pstr = malloc(sizeof(*pstr));
		if (!pstr)
			goto err3;
		pstr->s0 = key;
		pstr->s1 = value;
		LIST_INSERT_BEFORE(&tail, pstr, link);
	}
	LIST_REMOVE(&tail, link);

	/* Parse done, return the config list node. */
	return l;
err3:
	free(value);
err2:
	free(key);
	/* Reuse pstr */
	while ((pstr = LIST_FIRST(&l->arg_head_s))) {
		LIST_REMOVE(pstr, link);
		bpair_str_free(pstr);
	}
err1:
	free(l);
err0:
	return NULL;
}

int process_cmd_plugin(struct bconfig_list *cfg)
{
	int rc;
	struct bpair_str *bp = bpair_str_search(&cfg->arg_head_s, "name", NULL);
	if (!bp)
		return EINVAL;
	if (strncmp(bp->s1, "bin", 3) == 0) {
		return load_plugin(cfg, &bip_head_s);
	}
	else if (strncmp(bp->s1, "bout", 4) == 0) {
		rc = load_plugin(cfg, &bop_head_s);
		if (rc)
			return rc;
		/* An output plugin needs an output queue */
		struct boutplugin *p = (typeof(p))LIST_FIRST(&bop_head_s);
		p->_outq = get_least_busy_boutq();
		return 0;
	}
	return EINVAL;
}

struct __process_cmd_tokens_line_ctxt {
	btkn_type_t tkn_type;
	bstore_t store;
	union {
		char _buff[1024 + sizeof(struct bstr)];
		struct bstr bstr;
	};
};

static
int __process_cmd_tokens_line_cb(char *line, void *_ctxt)
{
	struct __process_cmd_tokens_line_ctxt *ctxt = _ctxt;
	char *id_str;
	int n;
	int spc_idx;
	uint32_t tkn_id = 0;
	int has_tkn_id = 0;
	int len;

	/* Get rid of leading spaces, trailing spaces have been eliminated before
	 * this callback. */
	while (*line && isspace(*line)) {
		line++;
	}
	if (!*line)
		return 0; /* skip empty line */
	/* prep token */
	n = sscanf(line, "%*s%n %u", &spc_idx, &tkn_id);
	if (n==1) {
		/* has tkn_id */
		has_tkn_id = 1;
		line[spc_idx] = 0;
	}
	len = strlen(line);
	if (len > 1023) {
		berr("token too long: %s", line);
		return 0;
	}
	btkn_t tkn = btkn_alloc(tkn_id,
				BTKN_TYPE_MASK(ctxt->tkn_type),
				line,
				strlen(line));
	if (has_tkn_id) {
		if (ctxt->tkn_type == BTKN_TYPE_TYPE)
			tkn->tkn_type_mask |= BTKN_TYPE_MASK(tkn_id);
		if (bstore_tkn_add_with_id(ctxt->store, tkn)) {
			berr("error inserting token '%s' with id %d\n", line, tkn_id);
		}
	} else {
		tkn_id = bstore_tkn_add(ctxt->store, tkn);
		if (!tkn_id) {
			berr("error inserting token '%s'", line);
		}
	}
	btkn_free(tkn);
	return 0;
}

/**
 * \returns 0 on success.
 * \returns Error code on error.
 */
int process_cmd_tokens(struct bconfig_list *cfg)
{
	struct bpair_str *bp_path = bpair_str_search(&cfg->arg_head_s, "path",
									NULL);
	struct bpair_str *bp_type = bpair_str_search(&cfg->arg_head_s, "type",
									NULL);
	if (!bp_path || !bp_type)
		return EINVAL;

	struct __process_cmd_tokens_line_ctxt *ctxt = malloc(sizeof(*ctxt));
	if (!ctxt) {
		return ENOMEM;
	}
	const char *path = bp_path->s1;
	ctxt->tkn_type = btkn_type_from_str(bp_type->s1);
	if (ctxt->tkn_type < BTKN_TYPE_FIRST
			|| BTKN_TYPE_LAST < ctxt->tkn_type) {
		berr("Invalid token type '%s' specified in configuration file.\n", bp_type->s1);
		exit(1);
	}
	ctxt->store = bstore;
	int rc = bprocess_file_by_line_w_comment(path,
					__process_cmd_tokens_line_cb, ctxt);

cleanup:
	if (ctxt)
		free(ctxt);
	return rc;
}

/**
 * Process the given command \c cmd.
 * \param cmd The command to process.
 * \return 0 on success.
 * \return Error code on error.
 */
int process_command(const char *cmd)
{
	struct bconfig_list *cfg = parse_config_str(cmd);
	int rc = 0;

	if (!cfg) {
		rc = errno;
		goto out;
	}

	switch (bcfg_cmd_str2enum(cfg->command)) {
	case BCFG_CMD_PLUGIN:
		rc = process_cmd_plugin(cfg);
		break;
	case BCFG_CMD_TOKENS:
		rc = process_cmd_tokens(cfg);
		break;
	default:
		/* Unknown command */
		berr("Unknown command: %s", cfg->command);
		rc = EINVAL;
	}

	bconfig_list_free(cfg);
out:
	return rc;
}

/**
 * Configuration file handling function.
 */
void config_file_handling(const char *path)
{
	FILE *fin = fopen(path, "rt");
	if (!fin) {
		perror("Cannot open configuration file");
		exit(-1);
	}
	char buff[1024];
	int lno = 0;
	int rc = 0;
	char *s;
	while (fgets(buff, 1024, fin)) {
		lno++;
		/* eliminate trailing spaces */
		s = buff + strlen(buff) - 1;
		while (isspace(*s))
			*s = '\0';
		/* eliminate preceding white spaces */
		s = buff;
		while (isspace(*s))
			s++;
		if (*s == '#' || *s == '\0')
			continue; /* comment or empty line */
		if ((rc = process_command(s))) {
			berr("process_command error %d: %s at %s:%d\n",
					rc, strerror(rc), path, lno);
			exit(rc);
		}
	}
	fclose(fin);
}

#ifdef ENABLE_OCM
/* This is an interface to the existing baler configuration */
void process_ocm_cmd(ocm_cfg_cmd_t cmd)
{
	struct bconfig_list *bl;
	struct bpair_str *bp;
	struct bpair_str *blast;
	struct ocm_av_iter iter;
	const char *key;
	const struct ocm_value *v;

	bl = calloc(1, sizeof(*bl));
	if (!bl) {
		berr("%m at %s:%d in %s\n", __FILE__, __LINE__, __func__);
		return;
	}

	/* Create baler command from ocm command */
	ocm_av_iter_init(&iter, cmd);
	bl->command = (char*)ocm_cfg_cmd_verb(cmd);
	blast = NULL;
	while (ocm_av_iter_next(&iter, &key, &v) == 0) {
		bp = calloc(1, sizeof(*bp));
		bp->s0 = (char*)key;
		bp->s1 = (char*)v->s.str;
		if (!blast)
			LIST_INSERT_HEAD(&bl->arg_head_s, bp, link);
		else
			LIST_INSERT_AFTER(blast, bp, link);
		blast = bp;
	}
	/* end create baler command */

	/* Process the command */
	switch (bcfg_cmd_str2enum(bl->command)) {
	case BCFG_CMD_PLUGIN:
		process_cmd_plugin(bl);
		break;
	case BCFG_CMD_TOKENS:
		process_cmd_tokens(bl);
		break;
	default:
		/* Unknown command */
		berr("Unknown command: %s", bl->command);
	}

cleanup:
	while ((bp = LIST_FIRST(&bl->arg_head_s))) {
		LIST_REMOVE(bp, link);
		free(bp);
	}
	free(bl);
}

void process_ocm_cfg(ocm_cfg_t cfg)
{
	ocm_cfg_cmd_t cmd;
	struct ocm_cfg_cmd_iter iter;
	ocm_cfg_cmd_iter_init(&iter, cfg);
	while (ocm_cfg_cmd_iter_next(&iter, &cmd) == 0) {
		process_ocm_cmd(cmd);
	}
}

int ocm_cb(struct ocm_event *e)
{
	switch (e->type) {
	case OCM_EVENT_CFG_REQUESTED:
		ocm_event_resp_err(e, ENOSYS, ocm_cfg_req_key(e->req),
							"Not implemented.");
		break;
	case OCM_EVENT_CFG_RECEIVED:
		process_ocm_cfg(e->cfg);
		break;
	case OCM_EVENT_ERROR:
		berr("ocm event error, key: %s, code: %d, msg: %s",
				ocm_err_key(e->err),
				ocm_err_code(e->err),
				ocm_err_msg(e->err));
		break;
	default:
		/* do nothing, but suppressing compilation warning */
		break;
	}
	return 0;
}
#endif

void handle_set_log_file(const char *path)
{
	log_path = strdup(path);
	if (!log_path) {
		perror(path);
		exit(-1);
	}

	int rc = blog_open_file(log_path);
	if (rc) {
		fprintf(stderr, "Failed to open the log file '%s'\n", path);
		exit(rc);
	}
}

/**
 * Configuration handling.
 * Currently, just do stuffs from the command line. This function needs to be
 * changed later to receive the real configuration from the configuration
 * manager.
 */
void args_handling(int argc, char **argv)
{
	int c;
	int len;
	int rc;

	bset_store_path("./store");
	bset_store_plugin("bstore_sos");
	blog_set_level(BLOG_LV_WARN);

next_arg:
	c = getopt(argc, argv, optstring);
	switch (c) {
	case 'l':
		handle_set_log_file(optarg);
		break;
	case 's':
		bset_store_path(optarg);
		break;
	case 'S':
		bset_store_plugin(optarg);
		break;
	case 'F':
		is_foreground = 1;
		break;
	case 'C':
		config_path = strdup(optarg);
		break;
#ifdef ENABLE_OCM
	case 'z':
		ocm_port = atoi(optarg);
		break;
#endif
	case 'h':
		m_host = optarg;
		break;
	case 'v':
		rc = blog_set_level_str(optarg);
		if (rc) {
			berr("Invalid verbosity level: %s", optarg);
			exit(-1);
		}
		break;
	case 'I':
		binqwkrN = atoi(optarg);
		break;
	case 'O':
		boutqwkrN = atoi(optarg);
		break;
	case 'Q':
		qdepth = atoi(optarg);
		break;
	case 'V':
		printf("Version: %s\n", bversion());
		printf("  GIT-SHA: %s\n", bgitsha());
		printf("  GIT-TAG: %s\n", bgittag());
		exit(0);
		break;
	case '?':
		display_help_msg();
		exit(0);
	case -1:
		goto arg_done;
	}
	goto next_arg;

arg_done:
	binfo("Baler Daemon Started.\n");
}

void binq_data_print(struct binq_data *d)
{
	printf("binq: %.*s %ld (%d): ", d->hostname->blen, d->hostname->cstr,
			d->tv.tv_sec, d->tkn_count);
	struct bstr_list_entry *e;
	LIST_FOREACH(e, &d->tokens, link) {
		printf(" '%.*s'", e->str.blen, e->str.cstr);
	}
	printf("\n");
}

static int queue_output(bmsg_t msg)
{
	int rc = 0;
	struct bplugin *p;
	LIST_FOREACH(p, &bop_head_s, link) {
		/* Copy msg to omsg for future usage in output queue. */
		struct bmsg *omsg = bmsg_alloc(msg->argc);
		if (!omsg) {
			rc = ENOMEM;
			break;
		}
		memcpy(omsg, msg, BMSG_SZ(msg));
		/* Prepare output queue entry. */
		struct bwq_entry *oent = malloc(sizeof(*oent));
		if (!oent) {
			bmsg_free(omsg);
			rc = ENOMEM;
			break;
		}
		struct boutq_data *odata = &oent->data.out;
		odata->comp_id = msg->comp_id;
		odata->tv = msg->timestamp;
		odata->msg = omsg;
		odata->plugin = (struct boutplugin *)p;
		bwq_nq(boutq, oent);
	}
	return rc;
}

/**
 * Core processing of an input entry.
 * \param ent Input entry.
 * \param ctxt The context of the worker.
 * \return 0 on success.
 * \return errno on error.
 */
static int process_input_entry(struct bwq_entry *bwq_ent, void *arg)
{
	int rc;
	binq_data_t in_data = &bwq_ent->data.in;
	bcomp_id_t comp_id;
	uint64_t tkn_id;
	int tkn_idx;
	struct bstr *ptn;
	struct bmsg *msg;
	btkn_tailq_entry_t ent;

	rc = EINVAL;
	if (in_data->type != BINQ_DATA_MSG)
		goto err_0;

	rc = ENOMEM;
	ptn = bstr_alloc(in_data->tkn_count * sizeof(uint64_t));
	if (!ptn)
		goto err_0;

	msg = bmsg_alloc(in_data->tkn_count);
	if (!msg)
		goto err_1;

	/*
	 * Add each token to the token store if not already present;
	 * in either case return it's unique token id.  Place this
	 * token id into a bstr in the field position this token
	 * occupied in the message.
	 */
	tkn_idx = 0;
	comp_id = 0;
	TAILQ_FOREACH(ent, &in_data->tkn_q, link) {
		btkn_type_t tkn_type = btkn_first_type(ent->tkn);
		ent->tkn->tkn_count = 1;
		tkn_id = bstore_tkn_add(bstore, ent->tkn);
		if (!tkn_id) {
			rc = errno;
			goto cleanup;
		}
		/*
		 * When the tkn comes from the parser, it hasn't
		 * discriminated between dictionary words, hostnames
		 * and plain text.
		 */
		if (btkn_has_type(ent->tkn, BTKN_TYPE_SERVICE))
			/* Service names may be dictionary words */
			tkn_type = BTKN_TYPE_SERVICE;
		if (btkn_has_type(ent->tkn, BTKN_TYPE_HOSTNAME))
			tkn_type = BTKN_TYPE_HOSTNAME;
		else if (btkn_has_type(ent->tkn, BTKN_TYPE_WORD))
			tkn_type = BTKN_TYPE_WORD;
		/*
		 * Pattern 'wildcards' are everyting except WORDs, WHITESPACEs
		 * or SEPARATORs, see `btkn_type_is_wildcard()` in btkn_types.h
		 */
		switch (tkn_type) {
		case BTKN_TYPE_SEPARATOR:
		case BTKN_TYPE_WORD:
		case BTKN_TYPE_WHITESPACE:
			ptn->u64str[tkn_idx] = (tkn_id << 8) | tkn_type;
			break;
		case BTKN_TYPE_HOSTNAME:
			/* Don't override the component id if a hostname
			 * appears a second time in the message */
			if (!comp_id)
				msg->comp_id = comp_id = tkn_id;
		default:
			ptn->u64str[tkn_idx] = (tkn_type << 8) | tkn_type;
		}
		assert(((64 + 7 - __builtin_clzl(ptn->u64str[tkn_idx])) >> 3) < 8);

		/* Message argument is always the token 'literal' */
		msg->argv[tkn_idx] = (tkn_id << 8) | tkn_type;
		tkn_idx++;
	}
	if (comp_id == 0 && in_data->hostname) {
		/* Use the hostname from the entry */
		btkn_t tkn = btkn_alloc(0, BTKN_TYPE_MASK(BTKN_TYPE_HOSTNAME),
					in_data->hostname->cstr,
					in_data->hostname->blen);
		tkn_id = bstore_tkn_add(bstore, tkn);
		msg->comp_id = tkn_id;
		btkn_free(tkn);
	}
	ptn->blen = tkn_idx * sizeof(uint64_t);
	msg->argc = tkn_idx;
	msg->timestamp = in_data->tv;
	msg->ptn_id = bstore_ptn_add(bstore, &in_data->tv, ptn);
	if (!msg->ptn_id) {
		berr("bstore_add_pattern() failed, errno: %d", errno);
		rc = errno;
		goto cleanup;
	}
	rc = queue_output(msg);
cleanup:
	binq_entry_free(bwq_ent);
	bmsg_free(msg);
 err_1:
	bstr_free(ptn);
 err_0:
	return rc;
}

/**
 * Routine for Input Queue Worker. When data are avialable in the input queue,
 * one of the input queue workers will get an access to the input queue.
 * It then consume the input entry and release the input queue lock so that
 * the other workers can work on the next entry.
 * \param arg Ignored
 * \return NULL (should be ignored)
 */
void* binqwkr_routine(void *arg)
{
	struct timeval start_time = { 0, 0 };
	struct timeval end_time = { 0, 0 };
	int inp_count = 0;
	struct bwq_entry *ent;
	sigset_t sigset;
	sigfillset(&sigset);
	pthread_sigmask(SIG_SETMASK, &sigset, NULL); /* block all signals */
	gettimeofday(&start_time, NULL);
loop:
	/* bwq_dq will block the execution if the queue is empty. */
	ent = bwq_dq(binq);
	if (!ent) {
		/* This is not supposed to happen. */
		berr("Error, ent == NULL\n");
	}
	if (!inp_count)
		gettimeofday(&start_time, NULL);
	if (process_input_entry(ent, (struct bin_wkr_ctxt*) arg) == -1) {
		/* XXX Do better error handling ... */
		berr("process input error ...");
	}
	inp_count++;
	gettimeofday(&end_time, NULL);
	double start = (double)start_time.tv_sec * 1.0e6 + (double)start_time.tv_usec;
	double end = (double)end_time.tv_sec * 1.0e6 + (double)end_time.tv_usec;
	double dur = (end - start) / 1.0e6;
	if (dur > 1) {
		printf("%p input messages/sec = %g\n",
		       (void *)(unsigned long)pthread_self(), inp_count / dur);
		inp_count = 0;
	}
	goto loop;
}

int process_output_entry(struct bwq_entry *ent, struct bout_wkr_ctxt *ctxt)
{
	int rc = 0;
	struct bplugin *p;
	LIST_FOREACH(p, &bop_head_s, link) {
		struct boutplugin *outp = (typeof(outp))p;
		rc = outp->process_output(outp, &ent->data.out);
		if (rc) {
			bwarn("Output plugin %s->process_output error, code:"
				       " %d\n", p->name, rc);
			break;
		}
	}
	return rc;
}

/**
 * Work routine for Output Queue Worker Thread.
 * \param arg A pointer to ::bout_wkr_ctxt.
 * \return Nothing as the worker thread(s) run forever.
 */
void* boutqwkr_routine(void *arg)
{
	int rc;
	struct bout_wkr_ctxt *octxt= arg;
	struct bwq_entry *ent;
	struct boutq_data *d;
	sigset_t sigset;
	sigfillset(&sigset);
	pthread_sigmask(SIG_SETMASK, &sigset, NULL); /* block all signals */
loop:
	/* bwq_dq will block the execution if the queue is empty. */
	ent = bwq_dq(&boutq[octxt->worker_id]);
	if (!ent) {
		/* This is not supposed to happen. */
		berr("Error, ent == NULL\n");
	}
	rc = ent->data.out.plugin->
		process_output(ent->data.out.plugin, &ent->data.out);
	if (rc)
		berr("process input error, code %d\n", errno);
	boutq_entry_free(ent);
	goto loop;
}

/**
 * Input Worker Thread & Output Worker Thread join point.
 */
void thread_join()
{
	int i;
	/* Joining the input queue workers */
	for (i=0; i<binqwkrN; i++){
		pthread_cancel(binqwkr[i]);
		pthread_join(binqwkr[i], NULL);
	}

	/* Joining the output queue workers */
	for (i=0; i<boutqwkrN; i++){
		pthread_cancel(boutqwkr[i]);
		pthread_join(boutqwkr[i], NULL);
	}
	struct bplugin *p;
	LIST_FOREACH(p, &bip_head_s, link)
		p->stop(p);
	LIST_FOREACH(p, &bop_head_s, link)
		p->stop(p);
}

/**
 * Daemon clean-up routine.
 */
void cleanup_daemon(int x)
{
	binfo("Cleaningup daemon ... (%s)", bsignalstr(x));
	binfo("Closing the store and syncing data...");
	fflush(stdout);

	/* Then join the worker threads. */
	thread_join();

	bstore_close(bstore);
	binfo("Terminating baler daemon.");
	exit(0);
}

/**
 * Action when receives SIGUSR1 from logrotate
 */
void handle_logrotate(int x)
{
	int rc = 0;
	rc = blog_rotate(log_path);
	if (rc) {
		berr("Failed to open a new log file. '%s'\n",
						strerror(errno));
		cleanup_daemon(x);
	}
}

/* signals that generate core dump from signal(7) */
int core_signals[] = {
	SIGQUIT,
	SIGILL,
	SIGABRT,
	SIGFPE,
	SIGSEGV,
	SIGBUS,
	SIGSYS,
	SIGTRAP,
	SIGXCPU,
	SIGXFSZ,
	SIGIOT,
	SIGUNUSED,
	0
};

/**
 * \brief The main function.
 */
int main(int argc, char **argv)
{
	struct sigaction cleanup_act, logrotate_act;
	siginfo_t siginfo;
	int sig;
	int i;
	sigset_t sigset;

	/* Mask all signals when the handler is invoked, except for the ones
	 * that cause core dump. */
	sigfillset(&sigset);
	for (i = 0; i < sizeof(core_signals)/sizeof(*core_signals); i++) {
		sigdelset(&sigset, core_signals[i]);
	}

	/* SIGHUP, SIGINT, and SIGTERM ==> cleanup_daemon() */
	cleanup_act.sa_handler = cleanup_daemon;
	cleanup_act.sa_flags = 0;
	cleanup_act.sa_mask = sigset;
	sigaction(SIGHUP, &cleanup_act, NULL);
	sigaction(SIGINT, &cleanup_act, NULL);
	sigaction(SIGTERM, &cleanup_act, NULL);

	/* SIGUSR1 ==> handle_logrotate() */
	/* also add SIGHUP, SIGINT, and SIGTERM into the mask */
	sigaddset(&sigset, SIGHUP);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	logrotate_act.sa_handler = handle_logrotate;
	logrotate_act.sa_flags = 0;
	logrotate_act.sa_mask = sigset;
	sigaction(SIGUSR1, &logrotate_act, NULL);

	/*
	 * Initialize before turning off all the signals or any fatal
	 * errors encountered will fail to exit the process.
	 */
	args_handling(argc, argv);
	initialize_daemon();
	if (config_path)
		config_file_handling(config_path);

	binfo("Baler is ready.");
	pause(); /* The main thread is dedicated for signal handling */
	assert(0 == "This should not be reached");
	return -1;
}
/**\}*/
