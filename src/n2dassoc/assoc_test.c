/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2017 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2017 Sandia Corporation. All rights reserved.
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

#include <assert.h>
#include <stdio.h>
#include <getopt.h>

#include "assoc.h"

/*
 * NOTE
 * ====
 *
 * Data Set
 * --------
 *
 * This test program generates < AAAA BBBB CCCC DDDD > binaries, which are used
 * as both IDs and data to calculate support. The value of binaries AAAA, BBBB,
 * CCCC, and DDDD are one of 0001, 0010, 0100, and 1000. In total, we have
 * 4*4*4*4 = 256 left-hand-side items.
 *
 * The right-hand-side items are:
 * 	- < 0000 0000 0000 1111 >,
 * 	- < 0000 0000 1111 0000 >,
 * 	- < 0000 1111 0000 0000 >,
 * 	- < 1111 0000 0000 0000 >,
 *
 *
 * Support
 * -------
 *
 * The `support( items )` is simply the number of 1 bits from `&` of all items.
 *
 *
 * Parameters
 * ----------
 *
 * Conf: 0.5
 * Diff: 0.1
 * Sig: 0.25
 *
 *
 * Expexted Rules
 * --------------
 *
 * The rules of 1 LHS item ({a}==>{x}) is impossible, because the confidence of
 * these rules could be either 0 or 0.25, which are less than 0.5.
 *
 * The rules of 2 LHS items ({a,b}==>{x}) are possible, e.g.
 * {<0001 0001 0001 0001>, <0010 0010 0001 0001>}==>{<0000 0000 0000 1111>}
 * (conf: 0.5), or
 * {<0001 0001 0001 0001>, <0010 0010 0010 0001>}==>{<0000 0000 0000 1111>}
 * (conf: 1.0).
 *
 * The rules of 3 LHS items will become redundant. Without loss of generality,
 * let's consider RHS of <1111 0000 0000 0000>. The 3-LHS will be in the form of
 * <AAAA #### #### ####>, otherwise, conf will be 0. To become a rule in our
 * setup (conf >= 0.5), the bitwise-and of the 3-LHS must have either 1 or 2
 * 1's (conf=1.0 and conf=0.5 respectively). If the bitwise-and has 3 1's, conf
 * will be 0.3 (not a rule). 4 1's is simply impossible.
 *
 * If there is a pair of items in the LHS has more than 1 position (the ####) of
 * different values, that pair (with the RHS) will form a rule. 2 different
 * position values will form a 0.5 conf rule, and 3 different position values
 * will form a 1.0 conf rule. 4 different position values trivially makes conf
 * 0. Thus, pairwise items in the 3-LHS rule that is not a redundant must have
 * exactly 1 different position value.
 *
 * Consider the case of conf = 1.0 (`&`LHS being <AAAA 0000 0000 0000>). WLOG,
 * Let's suppose the 1st and the 2nd item in the 3-LHS being <AAAA BBBB CCCC
 * DDDD> and <AAAA BBBB CCCC EEEE>. To achieve &LHS being <AAAA 0000 0000 0000>,
 * the 3rd item must be in the form of <AAAA XXXX CCCC ####>. Because the
 * pairwise different position must be exactly 1, the 1st item forces #### to be
 * DDDD, but the 2nd item forces the #### to be EEEE. Hence, the non-redundant
 * 3-LHS rule of conf 1.0 does not exist.
 *
 * Consider the case of conf = 0.5 (WLOG, &LHS being <AAAA BBBB 0000 0000>).
 * WLOG, Let's consider 1st and 2nd items being <AAAA BBBB CCCC DDDD> and <AAAA
 * BBBB CCCC EEEE> repectively. The 3rd item is then need to be in the form of
 * <AAAA BBBB XXXX ####>. Because the pairwise position difference must be 1,
 * the #### is forced to be DDDD by the 1st item, and EEEE by the 2nd item.
 * Hence, the non-redundant 3-LHS rule of conf 0.5 does not exist.
 *
 * For all 3-LHS valid candidates (conf = 1/3) will also be pruned due to 0
 * difference.
 *
 * Hence, we have only 2-LHS rules in this test environment. The total number of
 * such rules are:
 *   4*( (4*(4*3)^3)/2 + (4*3*4(4*3)^2)/2 ) = 27648
 *   (4 RHS * ( # conf-1.0 rules + # conf-0.5 rules ) )
 */

double support(int n, const item_id_t *ids, assoc_support_ctxt_t _arg)
{
	uint64_t x = ids[0];
	int i, count;
	for (i = 1; i < n; i++) {
		x &= ids[i];
	}
	for (count = 0; x; x >>= 1) {
		if (x & 0x1)
			count += 1;
	}
	return count;
}

int finalize(assoc_support_ctxt_t arg)
{
	/* DO NOTHING */
	printf("finalizing ... do nothing\n");
	return 0;
}

int main(int argc, char **argv)
{
	assoc_rule_file_t ar_file;
	assoc_t assoc;
	struct assoc_stat_s stat;
	item_id_t lhs[256];
	item_id_t rhs[4];
	int i, rc;
	uint64_t a,b,c,d;
	i = 0;
	for (i = 0; i < 256; i++) {
		a = 0x1 << (i & 0x3);
		b = 0x1 << ((i & (0x3<<2))>>2);
		c = 0x1 << ((i & (0x3<<4))>>4);
		d = 0x1 << ((i & (0x3<<6))>>6);
		lhs[i] = (d << 12) | (c << 8) | (b << 4) | a;
	}
	rhs[0] = 0xF;
	rhs[1] = 0xF << 4;
	rhs[2] = 0xF << 8;
	rhs[3] = 0xF << 12;

	struct assoc_param_s param = {
		.support = support,
		.finalize = finalize,
		.max_depth = 1024, /* shouldn't reach that depth */
		.threads = 4,
		.lhs_items = lhs,
		.lhs_n = 256,
		.rhs_items = rhs,
		.rhs_n = 4,
		.tmp_dir = "./tmp_dir",
		.ar_path = "./ar_file",
		.diff = 0.1,
		.conf = 0.5,
		.sig = 0.25,
	};

	assoc = assoc_new(&param);
	assert(assoc);
	rc = assoc_mine(assoc);
	assert(rc == 0);
	rc = assoc_wait(assoc);
	assert(rc == 0);
	rc = assoc_stat(assoc, &stat);
	assert(rc == 0);
	assoc_stat_print(stdout, &stat);
	assert(stat.rc == 0);
	assert(stat.rules == 27648);
	assoc_free(assoc);
	ar_file = assoc_rule_file_open("./ar_file");
	assert(ar_file);
	rc = assoc_rule_file_verify(ar_file);
	if (rc == 0) {
		printf("ar_file verified!\n");
	} else {
		printf("ar_file verify error: %d\n", rc);
	}
	assoc_rule_file_close(ar_file);
	return 0;
}
