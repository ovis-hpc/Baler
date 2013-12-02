/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2013 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2013 Sandia Corporation. All rights reserved.
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
 * \file binput.h
 * \author Narate Taerat (narate@ogc.us)
 *
 * \defgroup binput Baler Input Plugin Interface
 * \{
 * Input Plugin is essentially a bare regular plugin. The baler daemon core
 * expects an input plugin to run almost independently and receive input
 * messages from its input sources (yes, one input plugin instance should be
 * able to handle multiple input sources of the same kind). Once the plugin is
 * done first-round tokenizing, it should post the tokens into the input queue
 * ::binq using function ::binq_post. For more information about generic Baler
 * Plugin, please see \ref bplugin.
 */
#ifndef __BINPUT_H
#define __BINPUT_H

#include "btypes.h"
#include "bwqueue.h"
#include "bplugin.h"
#include <time.h>
#include <sys/queue.h>
#include <sys/times.h>
#include <sys/time.h>
#include <string.h>

/**
 * Post input entry \a e  to the input queue.
 * This function must be called when the input plugin finishes tokenizing the
 * message.
 * \note Once this function is called, it will own the input entry \a e, and
 * all of the tokens in it. The caller should not reuse any of the input entry
 * or tokens in it.
 * \param e The Baler Work Queue Entry (::bwq_entry)
 * \return 0 on success.
 * \return -1 on error.
 */
int binq_post(struct bwq_entry *e); /* binq_post impl. is in balerd.c */

#endif // __BINPUT_H
/**\}*/
