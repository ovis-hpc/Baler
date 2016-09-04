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
 * \file bin_rsyslog_tcp.c
 * \author Narate Taerat (narate@ogc.us)
 *
 * \defgroup rsyslog_parser rsyslog_parser rsyslog parser plugin
 * \{
 */
#include "baler/binput.h"
#include "baler/butils.h"

/**
 * This table contains unix time stamp for each hour of the day in each month.
 * Pre-determined these values are quicker than repeatedly calling mktime().
 * This table is initialized in the library constructor
 */
static
time_t ts_mdh[12][32][24];

/**
 * ts_ym[YEAR - 1900][MONTH - 1] contain timestamp of the beginning of the first
 * day of MONTH, YEAR. This is good from 1970 through 2199.
 */
static
time_t ts_ym[300][12] = {0};

/**
 * This table determine if a characcter is a delimiter or not.
 * This is also initialized in ::init_once().
 */
static
char is_delim[256];

static
char *delim = " \t,.:;`'\"<>\\/|[]{}()+-*=~!@#$%^&?";

static inline
time_t __get_utc_ts(int yyyy, int mm, int dd, int HH, int MM, int SS)
{
	return ts_ym[yyyy-1900][mm-1] + (3600*24)*(dd-1) + 3600*HH + 60*MM + SS;
}

/**
 * A convenient function to map 3 character month string to tm_mon number
 * (0 - 11).
 * \note This is a quick convenient function, hence it has no error checking.
 * \param s The string.
 * \return tm_mon number (0 - 11).
 * \return -1 on error.
 */
static
int __month3(char *s)
{
	uint32_t x = 0;
	memcpy(&x, s, 3);
	x = htole32(x);
	switch (x) {
	/* These are unsigned integer interpretation of 3-character strings
	 * in LITTLE ENDIAN. */
	case 0x6e614a: /* Jan */
	case 0x4e414a: /* JAN */
		return 0;
	case 0x626546: /* Feb */
	case 0x424546: /* FEB */
		return 1;
	case 0x72614d: /* Mar */
	case 0x52414d: /* MAR */
		return 2;
	case 0x727041: /* Apr */
	case 0x525041: /* APR */
		return 3;
	case 0x79614d: /* May */
	case 0x59414d: /* MAY */
		return 4;
	case 0x6e754a: /* Jun */
	case 0x4e554a: /* JUN */
		return 5;
	case 0x6c754a: /* Jul */
	case 0x4c554a: /* JUL */
		return 6;
	case 0x677541: /* Aug */
	case 0x475541: /* AUG */
		return 7;
	case 0x706553: /* Sep */
	case 0x504553: /* SEP */
		return 8;
	case 0x74634f: /* Oct */
	case 0x54434f: /* OCT */
		return 9;
	case 0x766f4e: /* Nov */
	case 0x564f4e: /* NOV */
		return 10;
	case 0x636544: /* Dec */
	case 0x434544: /* DEC */
		return 11;
	}
	/* On unmatched */
	return -1;
}

/**
 * This function extract an integer string from the input string and put the
 * parsed integer in \a *iptr.
 * \param[in,out] sptr (*sptr) is the input string, it will point to the
 * 	position after the consumed numbers when the function returned.
 * 	It will not change on error though.
 * \param[out] iptr (*ipt) is the result of the function.
 * \return 0 on success.
 * \return Error number on error.
 */
static inline
int get_int(char **sptr, int *iptr)
{
	char *s = *sptr;
	char buff[16];
	int i=0;
	while ('0'<=*s && *s<='9' && i<15) {
		buff[i] = *s;
		i++;
		s++;
	}
	if (i==0)
		return -1;
	buff[i] = 0; /* Terminate the buff string */
	*iptr = atoi(buff);
	*sptr = s;
	return 0;
}

/**
 * Get host token from the input string. The host is expected to be the first
 * token pointed by \a *sptr, and delimited by ' '.
 * \param[in,out] sptr (*sptr) is the input string. It will also be changed to
 * 	point at the end of the token.
 * \return A pointer to ::bstr containing the token, on success.
 * \return NULL on error.
 */
static
struct bstr* get_host(char **sptr)
{
	char *s = *sptr;
	while (*s && *s != ' ') {
		s++;
	}
	int len = s - *sptr;
	struct bstr *bstr = bstr_alloc(len);
	if (!bstr)
		return NULL;
	bstr->blen = len;
	memcpy(bstr->cstr, *sptr, len);
	*sptr = s;
	return bstr;
}

/**
 * Similar to ::get_host(), but this version does not allocate ::bstr.
 * \param sptr \a *sptr is an input string to extract the leading host from.
 * \param bstr The pre-allocated bstr structure.
 * \return The input parameter \a bstr (to keep it consistent to ::get_host()).
 * \return NULL if \a bstr->blen cannot hold the entire host token.
 */
static
struct bstr* get_host_r(char **sptr, struct bstr *bstr)
{
	char *s = *sptr;
	while (*s && *s != ' ') {
		s++;
	}
	int len = s - *sptr;
	if (bstr->blen < len)
		return NULL;
	bstr->blen = len;
	memcpy(bstr->cstr, *sptr, len);
	*sptr = s;
	return bstr;
}

static
int parse_msg_hdr_0(struct bstr *str, char *s, struct binq_data *d)
{
	int M, D, hh, mm, ss;
	/* Month */
	M = __month3(s);
	if (M == -1)
		return -1;
	s += 3;

	/* skip spaces */
	while (*s == ' ')
		s++;

	/* Day hh:mm:ss */
	if (get_int(&s, &D) == -1)
		return -1;

	if (*(s++) != ' ')
		return -1;

	if (get_int(&s, &hh) == -1)
		return -1;

	if (*(s++) != ':')
		return -1;

	if (get_int(&s, &mm) == -1)
		return -1;

	if (*(s++) != ':')
		return -1;

	if (get_int(&s, &ss) == -1)
		return -1;

	if (*(s++) != ' ')
		return -1;

	/* TODO XXX Handle daylight saving later
	 * NOTE Problem: currently the daylight saving is handled by mktime in
	 * ts_mdh initialization. However, the "fall back" hour won't be handled
	 * properly as the wall clock will just set back 1 hour, leaving the
	 * entire 2 hour of undetermined daylight saving time.
	 */
	d->tv.tv_sec = ts_mdh[M][D][hh] + 60*mm + ss;
	d->tv.tv_usec = 0; /* Default syslog does not support usec. */

	/* hostname */
	struct bstr *host;
	host = get_host(&s);
	if (!host)
		return -1;
	d->hostname = host;

	/* The rest is ' ' with the real message */
	return s - str->cstr;
}

static
int parse_msg_hdr_1(struct bstr *str, char *s, struct binq_data *d)
{
	/*
	 * s is expected to point at TIMESTAMP part of the rsyslog format
	 * ver 1 (see RFC5424 https://tools.ietf.org/html/rfc5424#section-6).
	 *
	 * Eventhough the header part in RFC5424 has more than TIMESTAMP and
	 * HOSTNAME, baler will care only TIMESTAMP and HOSTNAME. The rest of
	 * the header is treated as a part of the message.
	 */

	/* FULL-DATE T TIME */
	int dd,mm,yyyy;
	int HH,MM,SS,US = 0, TZH, TZM;
	int n, len;
	n = sscanf(s, "%d-%d-%dT%d:%d:%d%n.%d%n", &yyyy, &mm, &dd, &HH, &MM,
							&SS, &len, &US, &len);
	if (n < 6) {
		bwarn("Date-time parse error for message: %.*s", str->blen, str->cstr);
		errno = EINVAL;
		return -1;
	}
	/* Treat local wallclock as UTC wallclock, and adjust it later. */
	d->tv.tv_sec = __get_utc_ts(yyyy, mm, dd, HH, MM, SS);
	d->tv.tv_usec = US;
	s += len;
	switch (*s) {
	case 'Z':
		TZH = TZM = 0;
		s++;
		break;
	case '+':
	case '-':
		n = sscanf(s, "%d:%d%n", &TZH, &TZM, &len);
		if (n != 2) {
			bwarn("timezone parse error, msg: %.*s", str->blen, str->cstr);
		errno = EINVAL;
			return -1;
		}
		s += len;
		break;
	default:
		bwarn("timezone parse error, msg: %.*s", str->blen, str->cstr);
		errno = EINVAL;
		return -1;
	}
	/* adjust to UTC time */
	d->tv.tv_sec -= 3600 * TZH;
	d->tv.tv_sec -= 60 * TZM;

	/* expecting space */
	if (*s++ != ' ')
		return -1;

	/* hostname */
	struct bstr *host;
	host = get_host(&s);
	if (!host)
		return -1;
	d->hostname = host;

	return s - str->cstr;
}

/**
 * Parse message header.
 * \param str The ::bstr that contain original message.
 * \param[out] d The ::binq_data structure to contain parsed header information.
 * \return -1 on error.
 * \return Index \a i of \a str->cstr such that \a str->cstr[0..i-1] contains
 * 	message header information (e.g. Date, Time and hostname). The rest
 * 	(\a str->cstr[i..n]) is the message part, which also includes a leading
 * 	white space. In other words, \a i is the index next to the last index
 * 	that this function processed.
 */
static
int parse_msg_hdr(struct bstr *str, struct binq_data *d)
{
	char *s = str->cstr;
	/* Expecting '<###>' first. */
	if (*(s++) != '<')
		return -1;
	while ('0'<=*s && *s<='9') {
		s++;
	}
	if (*(s++) != '>')
		return -1;
	if (*s == '1')
		return parse_msg_hdr_1(str, s+2, d);
	/* If not version 1, assumes old format */
	return parse_msg_hdr_0(str, s, d);
}

/**
 * Extract the first token from \a *s. This function extract the first token and
 * create ::bstr_list_entry structure for the token and return it.
 * \param s (*s) is the input string, which will be changed to point to the
 * 	character next to the extracted token.
 * \return A pointer to ::bstr_list_entry on success.
 * \return NULL on error.
 */
static
struct bstr_list_entry* get_token(char **s)
{
	struct bstr_list_entry *ent;
	char *_s = *s;
	int len;
	if (!*_s)
		return NULL; /* Empty string */
	if (is_delim[*_s]) {
		len = 1;
		_s++;
		goto out;
	}
	/* else */
	while (*_s && !is_delim[*_s])
		_s++;
	len = _s - *s;
out:
	ent = bstr_list_entry_alloci(len, *s);
	if (!ent)
		return NULL;
	*s = _s;
	return ent;
}

/**
 * This function prepare ::bwq_entry from the given ::bstr \a s.
 * \param s The entire raw log message in ::bstr structure.
 * \return NULL on error.
 * \return A pointer to ::bwq_entry on success.
 */
static binp_result_t rsyslog_parse(binp_parser_t p, struct bstr *s, struct bwq_entry **pent)
{
	char *_s;
	struct bstr_list_head *tok_head;
	struct bstr_list_entry *tok_tail, *lent;
	binp_result_t res = BINP_ERR_RESOURCE;
	int count, midx;
	struct binq_data *d;
	struct bwq_entry *qent = calloc(1, sizeof(*qent));
	if (!qent)
		goto err0;
	bdebug("rsyslog: %.*s", s->blen, s->cstr);
	d = &qent->data.in;
	res = BINP_ERR_TIMESTAMP;
	/* First, handle the header part */
	midx = parse_msg_hdr(s, d);
	if (midx == -1)
		goto err1;

	/* Then, handle the rest of the tokens */
	tok_head = &d->tokens;
	LIST_INIT(tok_head);
	tok_tail = NULL;

	/* Start tokenizing */
	_s = s->cstr + midx + 1; /* skip the field delimiting ' ' */
	lent = NULL;
	count = 0;
	while (*_s && (lent = get_token(&_s))) {
		if (!tok_tail)
			LIST_INSERT_HEAD(tok_head, lent, link);
		else
			LIST_INSERT_AFTER(tok_tail, lent, link);

		tok_tail = lent;
		count++;
	}
	res = BINP_ERR_RESOURCE;
	if (!lent)
		/* Break out of the loop because lent == NULL ==> error */
		goto err1;

	d->tkn_count = count;
	*pent = qent;
	return BINP_OK;
err1:
	binq_entry_free(qent);
err0:
	berr("INPUT ERROR: %.*s", s->blen, s->cstr);
	return res;
}

/*
 * This function populates ::ts_ym global variable.
 */
static
void init_ts_ym()
{
	/* days of previous month */
	static int dpm[12] = {31, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30};
	int yyyy, mm, i;
	int Y;
	for (i = 70*12+1; i < (300*12); i++) {
		mm = i % 12;
		yyyy = i / 12;
		Y = 1900 + yyyy;
		ts_ym[yyyy][mm] = ts_ym[yyyy][mm-1] + dpm[mm]*24*60*60;
		if (mm == 2 && (Y % 4 == 0) &&
				((Y % 100 != 0) || (Y % 400 == 0))) {
			/* leap year: add Feb 29 before Mar 1. */
			ts_ym[yyyy][mm] += 24*60*60;
		}
	}
}

static const char* rsyslog_get_version(binp_parser_t p)
{
	static char biffle[256];
	sprintf(biffle, "1.1.1.1 %p", &is_delim[0]);
	return biffle;
}

const char *rsyslog_get_name(binp_parser_t p)
{
	return "rsyslog_parser";
}

void rsyslog_release(binp_parser_t p)
{
	free(p);
}

struct binp_parser rsyslog_parser = {
	.get_name = rsyslog_get_name,
	.get_version = rsyslog_get_version,
	.parse = rsyslog_parse,
	.release = rsyslog_release,
};

binp_parser_t binp_get_parser(void *d)
{
	binp_parser_t p = malloc(sizeof *p);
	if (!p)
		return p;
	*p = rsyslog_parser;
	return p;
}

static void __attribute__ ((constructor)) parser_init(void)
{
	time_t now = time(NULL);
	struct tm tm;
	(void)localtime_r(&now, &tm);

	/* Now, tm has the current year. Let's reset it and keep only the year
	 * and starts filling in the ::ts_mdh table. */
	tm.tm_min = 0;
	tm.tm_sec = 0;
	for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
		for (tm.tm_mday = 1; tm.tm_mday < 32; tm.tm_mday++) {
			for (tm.tm_hour = 0; tm.tm_hour < 24; tm.tm_hour++) {
				tm.tm_isdst = -1;
				ts_mdh[tm.tm_mon][tm.tm_mday][tm.tm_hour]
					= mktime(&tm);
			}
		}
	}
	init_ts_ym();
	bzero(is_delim, 256);
	int i;
	is_delim[0] = 1;
	for (i=0; i<strlen(delim); i++)
		is_delim[delim[i]] = 1;
}

static void __attribute__ ((destructor)) parser_term(void)
{
}

/**\}*/
