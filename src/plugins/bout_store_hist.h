/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2016 Open Grid Computing, Inc. All rights reserved.
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
#ifndef __BOUT_STORE_H
#define __BOUT_STORE_H

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include "baler/bplugin.h"
#include "baler/boutput.h"
#include "baler/bstore.h"

/**
 * \page bout_store_hist Baler Output Plugin for Histogram
 *
 * \section synopsis SYNOPSIS
 * <tt>
 * <b>plugin name=bout_store_hist</b>
 * 	[<b>tkn=</b>(0|1)]
 * 	[<b>ptn=</b>(0|1)]
 * 	[<b>ptn_tkn=</b>(0|1)]
 * </tt>
 *
 * \section description DESCRIPTION
 * \b bout_store_hist is a baler output plugin that receives processed messages
 * from \ref balerd "balerd" and further processes them into various histogram
 * data before storing them into \b bstore. Please see \ref
 * bout_store_hist_options section for more information of each histograms
 * processed by this plugin.
 *
 * \section bout_store_hist_options OPTIONS
 * \par tkn=(0|1) (optional, default: 0)
 * Disable (0) or enable (1) <b>token histogram</b> processing. A token
 * histogram tracks the number of occurrences of a token over time (by minutes,
 * hours, or days).
 *
 * \par ptn=(0|1) (optional, default: 0)
 * Disable (0) or enable (1) <b>pattern histogram</b> processing. A pattern
 * histogram, similarly to token histogram, tracks the number of occurrences of
 * a pattern over time (by minutes, hours, or days).
 *
 * \par
 * <b>Pattern-component histogram</b> processing is also enabled when the pattern
 * histogram processing is enabled. A pattern-component histogram tracks the
 * number of occurrences of a pattern on a component over time (by minutes,
 * hours, or days).
 *
 * \par ptn_tkn=(0|1) (optional, default: 0)
 * Disable (0) or enable (1) pattern-token histogram processing. A
 * <b>pattern-token histogram</b> tracks the number of occurrences of tokens in
 * a token position of a pattern. For example, if we have the following
 * messages:
 * \code
 * Successful su for root by bob
 * Successful su for root by alice
 * \endcode
 * and let's suppose we have the pattern <b>Successful * for root by *</b>, we
 * will have 'su' with count=2 in the first '*' position, and bob with count=1
 * and alice with count=1 in the 2nd '*' position.
 */

struct bout_store_hist_plugin {
	struct boutplugin base;
	pthread_mutex_t lock;
	bstore_t bs;
	int tkn_hist;
	int ptn_hist;
	int ptn_tkn_hist;
};

#endif
