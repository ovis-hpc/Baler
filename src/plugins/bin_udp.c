/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2016 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2016 Sandia Corporation. All rights reserved.
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
 * \file bin_udp.c
 * \author Tom Tucker (tom at ogc.us)
 *
 * \defgroup bin_udp Generic UDP input plugin
 * \{
 */
#include "baler/binput.h"
#include "baler/butils.h"
#include <limits.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>


#include <unistd.h>
#include <assert.h>

#define PLUGIN_DEFAULT_PORT 514u

static struct event_base *io_evbase;

typedef enum {
	PSTATUS_STOPPED=0,
	PSTATUS_RUNNING
} plugin_status_t;

/**
 * This structure stores context of this input plugin.
 */
struct plugin_ctxt {
	pthread_t io_thread;
	int io_fd;
	ssize_t max_msg_len;
	uint16_t port;
	binp_parser_t parser;
	int status;
};

/*
 * If there is no hostname token in the input, use the host that sent us the message
 */
void add_host(struct bwq_entry *ent, struct sockaddr_storage *ss, ssize_t name_len)
{
	char ip_str[128];
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	assert(name_len == sizeof(*sin));
	ent->data.in.hostname =
		bstr_alloc_init_cstr(inet_ntop(sin->sin_family, &sin->sin_addr,
					       ip_str, sizeof(ip_str)));
}

#define EVQ_DEPTH	16
static void* io_proc(void *arg)
{
	struct bplugin *this = arg;
	struct plugin_ctxt *ctxt = this->context;
	int fd_count, i, rc;
	struct sockaddr_in sin;
	struct sockaddr_storage msg_sin;
	struct epoll_event io_events[EVQ_DEPTH];
	ssize_t msg_len;
	struct msghdr msg;
	struct iovec iov;
	unsigned char *msg_buf;
	bstr_t str;
	struct bwq_entry *ent;

	ctxt->io_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctxt->io_fd < 0)
		goto err;

	sin.sin_addr.s_addr = 0;
	sin.sin_port = htons(ctxt->port);
	rc = bind(ctxt->io_fd, (struct sockaddr *)&sin, sizeof(sin));
	if (rc)
		goto err;

	msg_buf = malloc(ctxt->max_msg_len);
	if (!msg_buf)
		goto err;
	iov.iov_base = msg_buf;
	while (1) {
		msg_sin.ss_family = AF_UNIX;
		msg.msg_name = &msg_sin;
		msg.msg_namelen = sizeof(msg_sin);
		iov.iov_len = ctxt->max_msg_len;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
		msg_len = recvmsg(ctxt->io_fd, &msg, 0);
		str = bstr_alloc(msg_len+1);
		str->blen = msg_len;
		memcpy(str->cstr, msg_buf, msg_len);
		str->cstr[msg_len-1] = '\0';
		rc = ctxt->parser->parse(ctxt->parser, str, &ent);
		switch (rc) {
		case BINP_OK:
			if (!ent->data.in.hostname)
				/* Parser didn't set the hostname, use
				 * the address from the socket */
				add_host(ent, &msg_sin, msg.msg_namelen);
			binq_post(ent);
			break;
		case BINP_MORE:
			/* Need more input to complete message */
			break;
		default:
			berr("Error %d processing log message '%s'\n", rc, str->cstr);
			break;
		}
		bstr_free(str);
	}
 err:
	if (ctxt->io_fd >= 0)
		close(ctxt->io_fd);
	berr("io_proc() thread exit, rc: %d", rc);
	return NULL; /* return code abuse */
}

/**
 * This is called from the main daemon (through ::bplugin::config) to configure
 * the plugin before the main daemon calls ::plugin_start()
 * (through ::bplugin::start).
 * \param this The plugin.
 * \param arg_head The head of the list of arguments.
 * \return 0 on success.
 * \return errno on error.
 * \note Now only accept 'port' for _tcp plugin.
 */
static
int plugin_config(struct bplugin *this, struct bpair_str_head *arg_head)
{
	binp_get_parser_fn_t get_parser;
	void *lib;
	char libname[PATH_MAX];
	struct bpair_str *bpstr;
	struct plugin_ctxt *ctxt = this->context;
	int rc = 0;

	bpstr = bpair_str_search(arg_head, "port", NULL);
	if (bpstr)
		ctxt->port = atoi(bpstr->s1);

	bpstr = bpair_str_search(arg_head, "max_msg_len", NULL);
	if (bpstr)
		ctxt->max_msg_len = atoi(bpstr->s1);

	bpstr = bpair_str_search(arg_head, "parser", NULL);
	if (bpstr) {
		sprintf(libname, "lib%s.so", bpstr->s1);
		lib = dlopen(libname, RTLD_NOW);
		if (!lib) {
			char *msg = dlerror();
			if (msg)
				berr("dlopen: '%s'\n", msg);
			rc = ENOENT;
		}
		get_parser = dlsym(lib, "binp_get_parser");
		if (!get_parser) {
			berr("The library '%s' does not implement a Baler parser.\n",
			     libname);
			rc = EINVAL;
		}
		ctxt->parser = get_parser(lib);
		if (!ctxt->parser) {
			berr("Insufficient resources available to load '%s'.\n",
			     libname);
			rc = ENOMEM;
		}
	}
	return rc;
}

/**
 * This will be called from the main baler daemon to start the plugin
 * (through ::bplugin::start).
 * \param this The plugin instance.
 * \return 0 on success.
 * \return errno on error.
 */
static
int plugin_start(struct bplugin *this)
{
	struct plugin_ctxt *ctxt = this->context;
	int rc = pthread_create(&ctxt->io_thread, NULL, io_proc, this);
	if (rc)
		return rc;
	return 0;
}

/**
 * Calling this will stop the execution of \a this plugin.
 * \param this The plugin to be stopped.
 * \return 0 on success.
 * \return errno on error.
 */
static
int plugin_stop(struct bplugin *this)
{
	struct plugin_ctxt *ctxt = this->context;
	pthread_cancel(ctxt->io_thread);
	return 0;
}

/**
 * Free the plugin instance.
 * \param this The plugin to be freed.
 * \return 0 on success.
 * \note Now only returns 0, but the errors will be logged.
 */
static
int plugin_free(struct bplugin *this)
{
	/* If context is not null, meaning that the plugin is running,
	 * as it is set to null in ::plugin_stop(). */
	struct plugin_ctxt *ctxt = (typeof(ctxt)) this->context;
	int rc = 0;
	if (ctxt && ctxt->status == PSTATUS_RUNNING) {
		rc = plugin_stop(this);
		if (rc) {
			errno  = rc;
			berror("plugin_stop");
		}
		if (ctxt->io_fd >= 0)
			close(ctxt->io_fd);
	}
	bplugin_free(this);
	return 0;
}

#define UDP_MAX_MSG_LEN	4096
struct bplugin* create_plugin_instance()
{
	struct plugin_ctxt *ctxt = calloc(1, sizeof(*ctxt));
	struct bplugin *p = calloc(1, sizeof(*p));
	if (!p || !ctxt)
		goto err;
	p->name = strdup("bin_udp");
	p->version = strdup("0.1a");
	p->config = plugin_config;
	p->start = plugin_start;
	p->stop = plugin_stop;
	p->free = plugin_free;
	ctxt->status = PSTATUS_STOPPED;
	ctxt->port = PLUGIN_DEFAULT_PORT;
	ctxt->io_fd = -1;
	ctxt->max_msg_len = UDP_MAX_MSG_LEN;
	p->context = ctxt;
	return p;
 err:
	if (p) free(p);
	if (ctxt) free(ctxt);
	return NULL;
}

static char* ver()
{
	binfo("%s", "1.1.1.1");
	return "1.1.1.1";
}

/**\}*/
