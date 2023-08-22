%define api.prefix {__syslog__}
%{
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <time.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "baler/binput.h"
#include "baler/butils.h"
#include "baler/btkn_types.h"
#include "syslog.h"
#include <stdio.h>
/* #include "syslog_parser.h" */

#define YYDEBUG	1
#define YYERROR_VERBOSE 1

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
static time_t ts_ym[300][12] = {0};

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

void yyerror(struct syslog_parser *parser, struct bstr *input,
	     bwq_entry_t *pwqe, const char *str)
{
	int pos;
	fprintf(stderr, "%s\n", input->cstr);
	for (pos = 0; pos < parser->cpos; pos++)
	    fprintf(stderr, " ");
	fprintf(stderr, "^\n");
	fprintf(stderr, "%s\n", str);
	if (*pwqe) {
	    binq_entry_free(*pwqe);
	    *pwqe = NULL;
	}
}

static const char* syslog_get_version(binp_parser_t p)
{
	return "1.0.0.0";
}

static const char *syslog_get_name(binp_parser_t p)
{
	return "syslog_parser";
}

void syslog_release(binp_parser_t p)
{
	free(p);
}

static int parse_timestamp(char *time_str, struct timeval *tv)
{
	extern long timezone;
	char *str = time_str;
	int dd, mm, yyyy;
	int HH, MM, SS, US = 0;
	int TZH = 0;
	int TZM = 0;
	int n, len;
	char p;
	struct tm tm;
	time_t t;
	char *s;

	/* There are 3 formats currently supported. By example:
	 * 2015-03-29T18:40:01-06:00
	 * 2015-03-29T18:40:01+06:00
	 * 2015-03-29T18:40:01Z
	 * 2015-03-29 18:40:01
	 * May 29 18:40:01
	 */
	/* Get the Y-M-D */
	n = sscanf(str, "%d-%d-%d%n", &yyyy, &mm, &dd, &len);
	if (n == 3) {
		str += len;
		switch (*str) {
		case 'T':
			/* TZ is present */
			str++;
			n = sscanf(str,
				   "%d:%d:%d%n.%d%n",
				   &HH, &MM, &SS, &len, &US, &len);
			if (n < 3) {
				bwarn("Incorrectly formatted time information %s.", str);
			}
			str += len;
			switch (*str) {
			case 'Z':
				break;
			case '+':
			case '-':
				n = sscanf(str, "%c%d:%d%n", &p, &TZH, &TZM, &len);
				if (n != 3) {
					TZH =  TZM = 0;
					bwarn("Ignoring incorrectly formatted timezone information %s.", str);
				}
				if (p == '-') {
					TZH = -TZH;
					TZM = -TZM;
				}
				break;
			default:
				goto err;
			}
			break;
		case ' ':
			/* TZ is not present */
			/* Need strptime + mktime to handle daylight-saving */
			s = strptime(time_str, "%F %T", &tm);
			if (!s) {
				bwarn("Date-time parse error for message: %s", str);
				return 0;
			}
			t = mktime(&tm);
			tv->tv_sec = t;
			tv->tv_usec = 0;
			return 0;
		default:
			goto err;
		}
	} else {
		memset(&tm, 0, sizeof(tm));

		/* Initialize tm with localtime data */
		t = time(NULL);
		localtime_r(&t, &tm);

		/* This will only change the elements of tm specified in the string */
		s = strptime(str, "%h %d %T", &tm);
		if (!s) {
			bwarn("Date-time parse error for message: %s", str);
			return 0;
		}
		t = mktime(&tm);
		tv->tv_sec = t;
		tv->tv_usec = 0;
		return 0;
	}
	tv->tv_sec = __get_utc_ts(yyyy, mm, dd, HH, MM, SS);
	tv->tv_sec -= 3600 * TZH;
	tv->tv_sec -= 60 * TZM;
	tv->tv_usec = US;
	return 0;

 err:
	bwarn("Error parsing the time string %s into a Unix timestamp\n", time_str);
	return 1;
}

int __syslog__parse(syslog_parser_t parser, struct bstr *input, bwq_entry_t *pwqe);
void yy_delete_buffer(struct yy_buffer_state *);
int yylex(void*, syslog_parser_t, struct bstr *);

static binp_result_t
syslog_parse(binp_parser_t p, struct bstr *s, struct bwq_entry **pent)
{
	syslog_parser_t sp = (syslog_parser_t)p;
	int rc;
	*pent = NULL;
	if (sp->buffer_state) {
		/* The previous call did not reset the lexer state */
		yy_delete_buffer(sp->buffer_state);
		sp->cpos = 0;
		sp->buffer_state = NULL;
	}
	rc = __syslog__parse(sp, s, pent);
	if (rc)
	    return BINP_ERR_SYNTAX;
	return BINP_OK;
}

static struct syslog_parser syslog_parser = {
	.base = {
		.get_name = syslog_get_name,
		.get_version = syslog_get_version,
		.parse = syslog_parse,
		.release = syslog_release,
	},
	.cpos = 0
};

binp_parser_t binp_get_parser(void *d)
{
	struct syslog_parser *p = malloc(sizeof *p);
	if (!p)
		return NULL;
	*p = syslog_parser;
	return &p->base;
}

struct bwq_entry *alloc_wqe()
{
    struct bwq_entry *wqe = calloc(1, sizeof *wqe);
    wqe->data.in.format = BINQ_BTKN_QUEUE;
    wqe->data.in.type = BINQ_DATA_MSG;
    TAILQ_INIT(&wqe->data.in.tkn_q);
    return wqe;
}

void enqueue_token(struct bwq_entry *wqe, btkn_t tkn, btkn_type_t typ);

struct bwq_entry *yy_wqe = NULL;

%}

%define api.pure full
%lex-param {syslog_parser_t parser}
%lex-param {struct bstr *input}
%parse-param {syslog_parser_t parser}
%parse-param {struct bstr *input}
%parse-param {bwq_entry_t *pwqe}

%token PRIORITY_TKN
%token VERSION_TKN
%token TIMESTAMP_TKN
%token HOSTNAME_TKN
%token SERVICE_TKN
%token PID_TKN
%token TEXT_TKN
%token IP4_ADDR_TKN
%token IP6_ADDR_TKN
%token ETH_ADDR_TKN
%token HEX_INT_TKN
%token DEC_INT_TKN
%token FLOAT_TKN
%token PATH_TKN
%token URL_TKN
%token WHITESPACE_TKN
%token SEPARATOR_TKN
%token BSD_SVC_TKN

%%

log_msg:	msg_header
		{
		    *pwqe = yy_wqe;
		    yy_wqe = NULL;
		}
		| msg_header msg_token_list
		{
		    *pwqe = yy_wqe;
		    yy_wqe = NULL;
		}
		;

timestamp: 	TIMESTAMP_TKN
		{
		    if (!yy_wqe)
			yy_wqe = alloc_wqe();
		    parse_timestamp($1->tkn_str->cstr, &yy_wqe->data.in.tv);
		    btkn_free($1);
		}
		;

ts_wspace:	timestamp WHITESPACE_TKN
		{
		    btkn_free($2);
		}
		;

prio_vers:	PRIORITY_TKN DEC_INT_TKN WHITESPACE_TKN
		{
		    if (!yy_wqe)
			yy_wqe = alloc_wqe();
		    /* we don't enqueue these tokens to the token string */
		    btkn_free($1);
		    btkn_free($2);
		    btkn_free($3);
		}
		;

hostname:	TEXT_TKN | IP4_ADDR_TKN | IP6_ADDR_TKN
		;

encap_host:	| SEPARATOR_TKN hostname SEPARATOR_TKN
		{
		    enqueue_token(yy_wqe, $1, BTKN_TYPE_SEPARATOR); /* [( */
		    enqueue_token(yy_wqe, $2, BTKN_TYPE_HOSTNAME);
		    enqueue_token(yy_wqe, $3, BTKN_TYPE_SEPARATOR); /* ]) */
		}
		;

hwerr_hdr: 	timestamp WHITESPACE_TKN SEPARATOR_TKN WHITESPACE_TKN
		TEXT_TKN
		{
		    enqueue_token(yy_wqe, $3, BTKN_TYPE_SEPARATOR);
		    enqueue_token(yy_wqe, $4, BTKN_TYPE_WHITESPACE);
		    enqueue_token(yy_wqe, $5, BTKN_TYPE_WORD); /* HWERR */
		} encap_host
		;

bsd_hdr:	PRIORITY_TKN timestamp WHITESPACE_TKN BSD_SVC_TKN SEPARATOR_TKN
		{
		    btkn_free($1); /* free the PRIORITY_TKN */
		    btkn_free($3); /* free the WHITESPACE_TKN */
		    enqueue_token(yy_wqe, $4, BTKN_TYPE_SERVICE);
		    enqueue_token(yy_wqe, $5, BTKN_TYPE_SEPARATOR);
		}
		;

/* log message w/o priority and version */
ts_host:	timestamp WHITESPACE_TKN hostname
		{
		    btkn_free($2); /* free the WHITESPACE_TKN */
		    enqueue_token(yy_wqe, $3, BTKN_TYPE_HOSTNAME);
		}
		| timestamp WHITESPACE_TKN encap_host
		{
		    btkn_free($2); /* free the WHITESPACE_TKN */
		}
		;

/* Missing syslog version */
prio_host:	PRIORITY_TKN timestamp WHITESPACE_TKN hostname
		{
		    btkn_free($1); /* free the PRIORITY_TKN */
		    btkn_free($3); /* free the WHITESPACE_TKN */
		    enqueue_token(yy_wqe, $4, BTKN_TYPE_HOSTNAME);
		}
		| PRIORITY_TKN timestamp WHITESPACE_TKN encap_host
		{
		    btkn_free($1); /* free the PRIORITY_TKN */
		    btkn_free($3); /* free the WHITESPACE_TKN */
		}
		;

/* log message with priority and version */
pv_ts_host:	prio_vers timestamp WHITESPACE_TKN hostname
		{
		    btkn_free($3); /* free the WHITESPACE_TKN */
		    enqueue_token(yy_wqe, $4, BTKN_TYPE_HOSTNAME);
		}
		| prio_vers timestamp WHITESPACE_TKN encap_host
		{
		    btkn_free($3); /* free the WHITESPACE_TKN */
		}
		;

pv_ts_host_pid:		/* service name is missing/nul */
		pv_ts_host WHITESPACE_TKN DEC_INT_TKN
		{
		    enqueue_token(yy_wqe, $2, BTKN_TYPE_WHITESPACE);
		    enqueue_token(yy_wqe, $3, BTKN_TYPE_PID);
		}
		;

pv_ts_host_svc:	pv_ts_host WHITESPACE_TKN TEXT_TKN
		{
		    enqueue_token(yy_wqe, $2, BTKN_TYPE_WHITESPACE);
		    enqueue_token(yy_wqe, $3, BTKN_TYPE_SERVICE);
		}
		;

pv_ts_host_svc_pid:
		pv_ts_host_svc WHITESPACE_TKN DEC_INT_TKN
		{
		    enqueue_token(yy_wqe, $2, BTKN_TYPE_WHITESPACE);
		    enqueue_token(yy_wqe, $3, BTKN_TYPE_PID);
		}
		;

msg_header:	ts_wspace
	|	hwerr_hdr
	|	bsd_hdr
	|	prio_vers hwerr_hdr
	|	ts_host
	|	prio_host
	|	pv_ts_host
	|	pv_ts_host WHITESPACE_TKN
		{
		    enqueue_token(yy_wqe, $2, BTKN_TYPE_WHITESPACE);
		}
	|	pv_ts_host SEPARATOR_TKN
		{
		    enqueue_token(yy_wqe, $2, BTKN_TYPE_SEPARATOR);
		}
	|	pv_ts_host_pid
	|	pv_ts_host_pid WHITESPACE_TKN
		{
		    enqueue_token(yy_wqe, $2, BTKN_TYPE_WHITESPACE);
		}
	|	pv_ts_host_pid SEPARATOR_TKN
		{
		    enqueue_token(yy_wqe, $2, BTKN_TYPE_SEPARATOR);
		}
	| 	pv_ts_host_svc
	| 	pv_ts_host_svc WHITESPACE_TKN
		{
		    enqueue_token(yy_wqe, $2, BTKN_TYPE_WHITESPACE);
		}
	| 	pv_ts_host_svc SEPARATOR_TKN
		{
		    enqueue_token(yy_wqe, $2, BTKN_TYPE_SEPARATOR);
		}
	|	pv_ts_host_svc_pid
		;

msg_token_list:	msg_token
	|	msg_token_list msg_token
	;

msg_token:	TEXT_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_TEXT); }
	|	PRIORITY_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_PRIORITY); }
	|	VERSION_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_VERSION); }
	|	SERVICE_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_SERVICE); }
	|	PID_TKN		{ enqueue_token(yy_wqe, $1, BTKN_TYPE_PID); }
	|	TIMESTAMP_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_TIMESTAMP); }
	|	HOSTNAME_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_HOSTNAME); }
	|	IP4_ADDR_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_IP4_ADDR); }
	|	IP6_ADDR_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_IP6_ADDR); }
	|	ETH_ADDR_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_ETH_ADDR); }
	|	HEX_INT_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_HEX_INT); }
	|	DEC_INT_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_DEC_INT); }
	|	FLOAT_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_FLOAT); }
	|	URL_TKN		{ enqueue_token(yy_wqe, $1, BTKN_TYPE_URL); }
	|	PATH_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_PATH); }
	|	SEPARATOR_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_SEPARATOR); }
	|	WHITESPACE_TKN	{ enqueue_token(yy_wqe, $1, BTKN_TYPE_WHITESPACE); }
	;

%%

void enqueue_token(struct bwq_entry *wqe, btkn_t tkn, btkn_type_t typ)
{
    btkn_tailq_entry_t e = malloc(sizeof *e);
    e->tkn = tkn;
    tkn->tkn_type_mask = BTKN_TYPE_MASK(typ);
    TAILQ_INSERT_TAIL(&wqe->data.in.tkn_q, e, link);
    wqe->data.in.tkn_count++;
    if (typ == BTKN_TYPE_HOSTNAME)
	wqe->data.in.hostname = bstr_dup(tkn->tkn_str);
}

static void __attribute__ ((constructor)) parser_lib_init(void)
{
	tzset();
	init_ts_ym();
}

static void __attribute__ ((destructor)) parser_lib_term(void)
{
}
