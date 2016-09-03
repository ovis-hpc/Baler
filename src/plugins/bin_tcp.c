/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2015 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2015 Sandia Corporation. All rights reserved.
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
 * \file bin_tcp.c
 * \author Narate Taerat (narate@ogc.us)
 *
 * \defgroup bin_tcp Generic TCP input plugin
 * \{
 */
#include "baler/binput.h"
#include "baler/butils.h"
#include <limits.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/thread.h>

#include <unistd.h>
#include <assert.h>

#define PLUGIN_DEFAULT_PORT 54321u

static struct event_base *io_evbase;

typedef enum {
	PSTATUS_STOPPED=0,
	PSTATUS_RUNNING
} plugin_status_t;

/**
 * This structure stores context of this input plugin.
 */
struct plugin_ctxt {
	pthread_t io_thread; /**< Thread handling socket IO. */
	pthread_t conn_req_thread; /**< Thread handling conn req. */
	uint16_t port; /**< Port number to listen to. */
	binp_parser_t parser;
	int status; /**< Status of the plugin. */
};

/**
 * Context for a bufferevent socket connection.
 * Now only contain plugin, but might have more stuffs
 * later ...
 */
struct conn_ctxt {
	struct bplugin *plugin; /**< Plugin instance. */
	struct sockaddr_in sin;
	LIST_ENTRY(conn_ctxt) link;
};

LIST_HEAD(, conn_ctxt) conn_ctxt_list = LIST_HEAD_INITIALIZER();
pthread_mutex_t conn_ctxt_list_mutex = PTHREAD_MUTEX_INITIALIZER;

static
struct conn_ctxt *conn_ctxt_alloc(struct bplugin *bplugin,
				  struct sockaddr_in *sin)
{
	struct conn_ctxt *ctxt = calloc(1, sizeof(*ctxt));
	if (ctxt) {
		pthread_mutex_lock(&conn_ctxt_list_mutex);
		LIST_INSERT_HEAD(&conn_ctxt_list, ctxt, link);
		pthread_mutex_unlock(&conn_ctxt_list_mutex);
		ctxt->plugin = bplugin;
		ctxt->sin = *sin;
	}
	return ctxt;
}

/**
 * Function for freeing connection context.
 * \param ctxt The context to be freed.
 */
static
void conn_ctxt_free(struct conn_ctxt *ctxt)
{
	pthread_mutex_lock(&conn_ctxt_list_mutex);
	LIST_REMOVE(ctxt, link);
	pthread_mutex_unlock(&conn_ctxt_list_mutex);
	free(ctxt);
}

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

/**
 * Read callback for bufferevent.
 * \note 1 \a bev per connection.
 * \param bev The bufferevent object.
 * \param arg Pointer to ::conn_ctxt.
 */
static
void read_cb(struct bufferevent *bev, void *arg)
{
	struct conn_ctxt *cctxt = (struct conn_ctxt *)arg;
	struct plugin_ctxt *pctxt = cctxt->plugin->context;
	struct evbuffer_ptr evbptr;
	struct evbuffer *input = bufferevent_get_input(bev);
	struct bstr *str;
	struct bwq_entry *ent;
	int len, rc;
	do {
		/* Look for '\n' in the buffer as it is the end of each message. */
		evbptr = evbuffer_search(input, "\n", 1, NULL);
		if (evbptr.pos == -1)
			break;
		str = bstr_alloc(evbptr.pos+1);
		if (!str) {
			berror("bstr_alloc");
			break;
		}
		str->blen = evbptr.pos+1;
		len = evbuffer_remove(input, str->cstr, str->blen);
		if (len != str->blen) {
			berr("Expecting %d bytes, but only %d bytes were present.",
			     str->blen, len);
		}
		/* Eliminate the '\n' and terminate the string */
		str->cstr[str->blen-1] = 0;
		rc = pctxt->parser->parse(pctxt->parser, str, &ent);
		switch (rc) {
		case BINP_OK:
			if (!ent->data.in.hostname)
				/* Parser didn't set the hostname, use
				 * the address from the socket */
				add_host(ent,
					 (struct sockaddr_storage *)&cctxt->sin,
					 sizeof(cctxt->sin));
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
	} while (1);
}

/**
 * Event handler on bufferevent (in libevent).
 * \param bev The buffer event instance.
 * \param events The events.
 * \param arg The pointer to connection context ::conn_ctxt.
 */
static
void event_cb(struct bufferevent *bev, short events, void *arg)
{
	if (events & BEV_EVENT_ERROR) {
		berror("BEV_EVENT_ERROR");
	}
	if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
		#if DEBUG_BALER_CONN
		struct conn_ctxt *ctxt = arg;
		union {uint8_t a[4]; uint32_t u32;} ipaddr;
		uint16_t port;
		ipaddr.u32 = ctxt->sin.sin_addr.s_addr;
		port = be16toh(ctxt->sin.sin_port);
		binfo("%d.%d.%d.%d:%d disconnected",
			(int)ipaddr.a[0],
			(int)ipaddr.a[1],
			(int)ipaddr.a[2],
			(int)ipaddr.a[3],
			port
			);
		#endif
		bufferevent_free(bev);
		conn_ctxt_free(arg);
	}
}

/**
 * Connect callback. This function will be called when there is a connection
 * request coming in. This is a call back function for
 * evconnlistener_new_bind().
 * \param listener Listener
 * \param sock Socket file descriptor
 * \param addr Socket address ( sockaddr_in )
 * \param len Length of \a addr
 * \param arg Pointer to plugin instance.
 */
static
void conn_cb(struct event_base *evbase, int sock,
		struct sockaddr *addr, int len, void *arg)
{
	struct bufferevent *bev = NULL;
	struct conn_ctxt *cctxt = NULL;

	evutil_make_socket_nonblocking(sock);
	bev = bufferevent_socket_new(evbase, sock, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		berr("conn_cb(): bufferevent_socket_new() error, errno: %d",
			errno);
		goto cleanup;
	}
	cctxt = conn_ctxt_alloc(arg, (void*)addr);
	if (!cctxt) {
		berr("conn_cb(): malloc() error, errno: %d", errno);
	}
	cctxt->plugin = arg;
	bufferevent_setcb(bev, read_cb, NULL, event_cb, cctxt);
	bufferevent_enable(bev, EV_READ);
	#if DEBUG_BALER_CONN
	union {uint8_t a[4]; uint32_t u32;} ipaddr;
	uint16_t port;
	struct sockaddr_in *sin = (void*)addr;
	ipaddr.u32 = sin->sin_addr.s_addr;
	port = be16toh(sin->sin_port);
	binfo("connected from %d.%d.%d.%d:%d",
		(int)ipaddr.a[0],
		(int)ipaddr.a[1],
		(int)ipaddr.a[2],
		(int)ipaddr.a[3],
		port
		);
	#endif
	return;

cleanup:
	if (bev)
		bufferevent_free(bev); /* this will also close sock */
	if (cctxt)
		conn_ctxt_free(cctxt);
	if (!bev)
		close(sock);
	return;
}

/**
 * This is a pthread routine function for listening for connections from
 *  over TCP. pthread_create() function in ::plugin_start() will call
 * this function.
 * \param arg A pointer to the ::bplugin of this thread.
 * \retval (abuse)0 if there is no error.
 * \retval (abuse)errno if there are some error.
 * \note This is a thread routine.
 */
static
void* _tcp_listen(void *arg)
{
	int64_t rc = 0;
	struct bplugin *p = arg;
	struct plugin_ctxt *ctxt = p->context;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = INADDR_ANY },
		.sin_port = htons(ctxt->port)
	};
	struct sockaddr_in peer_addr;
	socklen_t peer_addr_len = sizeof(peer_addr);
	int peer_sd;
	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		rc = errno;
		goto out;
	}
	rc = bind(sd, (void*)&addr, sizeof(addr));
	if (rc) {
		rc = errno;
		goto out;
	}

	rc = listen(sd, 8192);
	if (rc) {
		rc = errno;
		goto out;
	}

	while (0 <= (peer_sd = accept(sd, (void*)&peer_addr, &peer_addr_len))) {
		conn_cb(io_evbase, peer_sd, (void*)&peer_addr, peer_addr_len, p);
		peer_addr_len = sizeof(peer_addr); /* set for next accept() */
	}

	berr("_tcp_listen(): accept() error, errno: %d", errno);
	rc = errno;

out:
	return (void*)rc;
}

void _dummy_cb(int fd, short what, void *arg)
{
	/* This should not be called */
	assert(0);
}

static
void* _tcp_io_ev_proc(void *arg)
{
	int rc = 0;
	struct event *dummy;
	io_evbase = event_base_new();
	struct bplugin *this = arg;
	struct plugin_ctxt *ctxt = this->context;
	if (!io_evbase) {
		rc = ENOMEM;
		goto err0;
	}

	/* dummy event to prevent the termination of event_base_dispatch() */
	dummy = event_new(io_evbase, -1, EV_READ, _dummy_cb, io_evbase);
	if (!dummy) {
		rc = ENOMEM;
		goto err1;
	}
	rc = event_add(dummy, NULL);
	if (rc) {
		goto err1;
	}

	/* Dedicated thread for socket accept() */
	rc = pthread_create(&ctxt->conn_req_thread, NULL, _tcp_listen, this);
	if (rc)
		goto err2;

	/* evbase will handle accepted socket IO */
	event_base_dispatch(io_evbase);

	/* clean up */
err2:
	event_free(dummy);
err1:
	event_base_free(io_evbase);
err0:
	berr("_tcp_ev_proc() thread exit, rc: %d", rc);
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
	if (bpstr) {
		uint16_t port = atoi(bpstr->s1);
		ctxt->port = port;
	}

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
	int rc = pthread_create(&ctxt->io_thread, NULL, _tcp_io_ev_proc, this);
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
	pthread_cancel(ctxt->conn_req_thread);
	pthread_cancel(ctxt->io_thread);
	pthread_join(ctxt->conn_req_thread, NULL);
	pthread_join(ctxt->io_thread, NULL);
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
	}
	bplugin_free(this);
	return 0;
}

/**
 * Global variable flag for ::init_once() function.
 */
static
int _once = 0;

static
pthread_mutex_t _once_mutex = PTHREAD_MUTEX_INITIALIZER;

static int init_once()
{
	int rc = 0;
	pthread_mutex_lock(&_once_mutex);
	_once = 1;
	rc = evthread_use_pthreads();
	if (rc)
		goto err0;
	goto out;
err0:
	_once = 0;
out:
	pthread_mutex_unlock(&_once_mutex);
	return rc;
}

struct bplugin* create_plugin_instance()
{
	if (!_once && init_once())
		return NULL;
	struct bplugin *p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;
	p->name = strdup("bin_tcp");
	p->version = strdup("0.1a");
	p->config = plugin_config;
	p->start = plugin_start;
	p->stop = plugin_stop;
	p->free = plugin_free;
	struct plugin_ctxt *ctxt = calloc(1, sizeof(*ctxt));
	ctxt->status = PSTATUS_STOPPED;
	ctxt->port = PLUGIN_DEFAULT_PORT;
	p->context = ctxt;
	return p;
}

static char* ver()
{
	binfo("%s", "1.1.1.1");
	return "1.1.1.1";
}

/**\}*/
