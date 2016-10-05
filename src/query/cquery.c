#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <getopt.h>
#include <errno.h>
#include <wordexp.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>

#include <time.h>
#include <dirent.h>

#include "baler/butils.h"
#include "baler/btkn.h"
#include "baler/bhash.h"
#include "baler/bset.h"
#include "baler/bheap.h"
#include "baler/bstore.h"

const char *short_opts = "s:S:P:n:y:B:E:A:W:I:Tmptcd123r";
struct option long_opts[] = {
	{"begin",       required_argument,      0, 'B'},
	{"color",	no_argument,		0, 'c'},
	{"comp_id",	required_argument,	0, 'C'},
	{"end",         required_argument,      0, 'E'},
	{"msg",		no_argument,		0, 'm'},
	{"ptn_hist",	no_argument,		0, '1'},
	{"bin_width",   required_argument,	0, 'W'},
	{"comp_hist",	no_argument,		0, '2'},
	{"tkn_hist",	no_argument,		0, '3'},
	{"ptn",		no_argument,		0, 'p'},
	{"ptn_id",	required_argument,	0, 'P'},
	{"ptn_tkn",	no_argument,		0, 'T'},
	{"arg",		required_argument,	0, 'A'},
	{"store",	required_argument,	0, 's'},
	{"plugin",	required_argument,	0, 'S'},
	{"tkn",		no_argument,		0, 't'},
	{"tkn_id",	required_argument,	0, 'I'},
	{"type",	required_argument,	0, 'y'},
	{"raw",	        required_argument,	0, 'r'},
	{0,		0,			0, 0},
};
void usage(int argc, char *argv[])
{
	printf("cquery -s <store> -{mpt}\n"
	       " --store,-s <store>     The path to the store.\n"
	       " --msg,-m               Query messages.\n"
	       " --ptn,-p               Query patterns.\n"
	       " --ptn_id,-P		Match the specified pattern id.\n"
	       " --ptn_tkn,-T		Query pattern tokens.\n"
	       " --arg,-A		Specifies which of the pattern arguments to display.\n"
	       " --tkn,-t               Query tokens.\n"
	       " --type,-y		Match the specified token type.\n"
	       " --color,-c             Decorate the tokens with color.\n"
	       " --begin,-B <ts>        Include patterns/messages first seen on or after <ts>.\n"
	       " --end,-E <ts>          Include patterns/messages on or before <ts>.\n"
	       "                        <ts> is formatted as follows:\n"
	       "                               \"yyyy-mm-dd HH:MM:SS\"\n"
	       " --comp_id,-C <list>    One or more comma separated component ids.\n"
	       " --ptn_hist, -1         Show the pattern history.\n"
	       " --comp_hist, -2        Show the component history.\n"
	       " --tkn_hist, -3         Show the token history.\n"
	       " --raw, -r              Show time as raw Unix timestamps.\n"
	       );
	exit(1);
}
// #define OUTP_DATE_FMT "%F %T"
#define OUTP_DATE_FMT "%c"
int raw_time = 0;
static const char *fmt_date(struct timeval *tv)
{
	size_t sz;
	struct tm *tm;
	static char date_str[80];
	time_t t = tv->tv_sec;
	if (!raw_time) {
		tm = localtime(&t);
		sz = strftime(date_str, sizeof(date_str), OUTP_DATE_FMT, tm);
	} else {
		sprintf(date_str, "%ld", t);
	}
	return date_str;
}

const char *ptn_type_strs[] = {
	[BTKN_TYPE_FIRST] = NULL,
	[BTKN_TYPE_TYPE] = "<type>",
	[BTKN_TYPE_PRIORITY] = "<prio>",
	[BTKN_TYPE_VERSION] = "<vers>",
	[BTKN_TYPE_TIMESTAMP] = "<ts>",
	[BTKN_TYPE_HOSTNAME] = "<host>",
	[BTKN_TYPE_SERVICE] = "<svc>",
	[BTKN_TYPE_PID] = "<pid>",
	[BTKN_TYPE_IP4_ADDR] = "<ip4>",
	[BTKN_TYPE_IP6_ADDR] = "<ip6>",
	[BTKN_TYPE_ETH_ADDR] = "<mac>",
	[BTKN_TYPE_HEX_INT] = "<hex>",
	[BTKN_TYPE_DEC_INT] = "<dec>",
	[BTKN_TYPE_SEPARATOR] = "<sep>",
	[BTKN_TYPE_FLOAT] = "<float>",
	[BTKN_TYPE_PATH] = "<path>",
	[BTKN_TYPE_URL] = "<url>",
	[BTKN_TYPE_WORD] = "<word>",
	[BTKN_TYPE_TEXT] = "*",
	[BTKN_TYPE_WHITESPACE] = " ",
	[BTKN_TYPE_LAST] = NULL,
};

const char *type_strs[] = {
	[BTKN_TYPE_FIRST] = NULL,
	[BTKN_TYPE_TYPE] = "<type>",
	[BTKN_TYPE_PRIORITY] = "<prio>",
	[BTKN_TYPE_VERSION] = "<vers>",
	[BTKN_TYPE_TIMESTAMP] = "<ts>",
	[BTKN_TYPE_HOSTNAME] = "<host>",
	[BTKN_TYPE_SERVICE] = "<svc>",
	[BTKN_TYPE_PID] = "<pid>",
	[BTKN_TYPE_IP4_ADDR] = "<ip4>",
	[BTKN_TYPE_IP6_ADDR] = "<ip6>",
	[BTKN_TYPE_ETH_ADDR] = "<mac>",
	[BTKN_TYPE_HEX_INT] = "<hex>",
	[BTKN_TYPE_DEC_INT] = "<dec>",
	[BTKN_TYPE_SEPARATOR] = "<sep>",
	[BTKN_TYPE_FLOAT] = "<float>",
	[BTKN_TYPE_PATH] = "<path>",
	[BTKN_TYPE_URL] = "<url>",
	[BTKN_TYPE_WORD] = "<word>",
	[BTKN_TYPE_TEXT] = "*",
	[BTKN_TYPE_WHITESPACE] = "<space>",
	[BTKN_TYPE_LAST] = NULL,
};

uint64_t min_cnt;
time_t begin_time;
time_t end_time;
time_t bin_width;
btkn_type_t tkn_type_id;
bptn_id_t tkn_id;
bptn_id_t ptn_id;
bcomp_id_t comp_id;
int color;

#define NORM  ""
#define BLUE  "\x1b[34m"
#define RED   "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define RESET "\x1b[0m"
#define BOLD  "\x1b[1m"

const char *type_colors[] = {
	[BTKN_TYPE_TYPE] = NORM,
	[BTKN_TYPE_PRIORITY] = NORM,
	[BTKN_TYPE_VERSION] = NORM,
	[BTKN_TYPE_TIMESTAMP] = NORM,
	[BTKN_TYPE_HOSTNAME] = BOLD GREEN,
	[BTKN_TYPE_SERVICE] = GREEN,
	[BTKN_TYPE_PID] = YELLOW,
	[BTKN_TYPE_IP4_ADDR] = NORM,
	[BTKN_TYPE_IP6_ADDR] = NORM,
	[BTKN_TYPE_ETH_ADDR] = NORM,
	[BTKN_TYPE_HEX_INT] = BOLD BLUE,
	[BTKN_TYPE_DEC_INT] = BOLD BLUE,
	[BTKN_TYPE_FLOAT] = BOLD BLUE,
	[BTKN_TYPE_PATH] = BOLD YELLOW,
	[BTKN_TYPE_URL] = BOLD YELLOW,
	[BTKN_TYPE_WORD] = BOLD,
	[BTKN_TYPE_SEPARATOR] = NORM,
	[BTKN_TYPE_WHITESPACE] = NORM,
	[BTKN_TYPE_TEXT] = BOLD RED,
	[BTKN_TYPE_LAST] = NULL,
};

void show_patterns(bstore_t bs)
{
	bptn_iter_t pi = bstore_ptn_iter_new(bs);
	bptn_t ptn;
	const char *tkn_str;
	printf("%-8s %-24s %-24s %-12s %s\n",
	       "Ptn Id", "First Seen", "Last Seen", "Msg Count", "Pattern");
	printf("-------- ------------------------ ------------------------ "
	       "------------ ------------\n");
	for (ptn = bstore_ptn_iter_find(pi, ptn_id); ptn; ptn = bstore_ptn_iter_next(pi)) {
		int arg;
		printf("%8lu ", ptn->ptn_id);
		printf("%-24s ", fmt_date(&ptn->first_seen));
		printf("%-24s ", fmt_date(&ptn->last_seen));
		printf("%12lu ", ptn->count);
		for (arg = 0; arg < ptn->tkn_count; arg++) {
			uint64_t tkn_id = (ptn->str->u64str[arg] >> 8);
			btkn_type_t tkn_type = ptn->str->u64str[arg] & 0xFF;
			btkn_t tkn = bstore_tkn_find_by_id(bs, tkn_id);
			assert(0 == (tkn_id & 0xFF000000));
			assert(tkn_type < 20);
			tkn_str = NULL;
			switch (tkn_type) {
			case BTKN_TYPE_WORD:
			case BTKN_TYPE_SEPARATOR:
				tkn_str = tkn->tkn_str->cstr;
				break;
			default:
				tkn_str = ptn_type_strs[tkn_type];
				break;
			}
			if (color)
				printf("%s", type_colors[tkn_type]);
			printf("%s", tkn_str);
			if (color)
				printf(RESET);
			if (tkn)
				btkn_free(tkn);
		}
		printf("\n");
		bptn_free(ptn);
	}
}

void show_ptn_tkns(bstore_t bs, bptn_id_t ptn_id, int pos)
{
	bptn_tkn_iter_t pi = bstore_ptn_tkn_iter_new(bs);
	bptn_t ptn;
	btkn_t tkn;
	const char *tkn_str;
	printf("%-12s %s\n", "Type", "Text");
	printf("------------ --------------------------------\n");
	ptn = bstore_ptn_find(bs, ptn_id);
	if (!ptn) {
		printf("Pattern %ld not found.\n", ptn_id);
		return;
	}
	size_t count = 0;
	for (tkn = bstore_ptn_tkn_iter_find(pi, ptn_id, pos);
	     tkn; tkn = bstore_ptn_tkn_iter_next(pi)) {
		char *type_str;
		btkn_type_t type_id = btkn_first_type(tkn);
		btkn_t type_tkn = bstore_tkn_find_by_id(bs, type_id);
		if (!type_tkn)
			type_str = "";
		else
			type_str = type_tkn->tkn_str->cstr;
		if (color) {
			if (type_id < BTKN_TYPE_LAST)
				printf("%s", type_colors[type_id]);
			else
				printf("%s", NORM);
		}
		printf("%-12s '%s'", type_str, tkn->tkn_str->cstr);
		if (color)
			printf(RESET);
		if (type_tkn)
			btkn_free(type_tkn);
		btkn_free(tkn);
		printf("\n");
		count++;
	}
	printf("------------ --------------------------------\n");
	printf("%zu Record(s)\n", count);
	bptn_free(ptn);
}

void show_ptn_hist(bstore_t bs)
{
	bptn_hist_iter_t pi = bstore_ptn_hist_iter_new(bs);
	struct bptn_hist_s hist, *p;
	size_t count = 0;

	hist.ptn_id = ptn_id;
	hist.bin_width = bin_width;
	hist.time = begin_time;

	printf("%-12s %-32s %-12s %-12s\n", "Ptn Id",
	       "Timestamp", "Bin Width(s)", "Msg Count");
	printf("------------ -------------------------------- ------------ ------------\n");
	for (p = bstore_ptn_hist_iter_find(pi, &hist);
	     p; p = bstore_ptn_hist_iter_next(pi, &hist)) {
		struct timeval tv;

		if (end_time && hist.time > end_time)
			break;

		tv.tv_sec = hist.time;
		tv.tv_usec = 0;
		printf("%12lu %-32s %12d %12lu\n",
		       hist.ptn_id,
		       fmt_date(&tv),
		       hist.bin_width,
		       hist.msg_count);
		count ++;
	}
	printf("------------ -------------------------------- ------------ ------------\n");
	printf("%zu Record(s)\n", count);
}

void show_tkn_hist(bstore_t bs)
{
	btkn_hist_iter_t pi = bstore_tkn_hist_iter_new(bs);
	struct btkn_hist_s hist, *p;
	size_t count = 0;

	hist.tkn_id = tkn_id;
	hist.bin_width = bin_width;
	hist.time = begin_time;

	printf("%-24s %-12s %-12s %-12s\n",
	       "Timestamp", "Tkn Id", "Bin Width (s)", "Occurances");
	printf("------------------------ ------------ ------------ ------------\n");
	for (p = bstore_tkn_hist_iter_find(pi, &hist);
	     p; p = bstore_tkn_hist_iter_next(pi, &hist)) {
		struct timeval tv;
		btkn_t tkn = bstore_tkn_find_by_id(bs, hist.tkn_id);

		if (end_time && hist.time > end_time)
			break;

		tv.tv_sec = hist.time;
		tv.tv_usec = 0;
		printf("%-24s %12lu %12d %12lu %s\n",
		       fmt_date(&tv),
		       hist.tkn_id,
		       hist.bin_width,
		       hist.tkn_count,
		       tkn->tkn_str->cstr);
		btkn_free(tkn);
		count ++;
	}
	printf("------------------------ ------------ ------------ ------------\n");
	printf("%zu Record(s)\n", count);
}

void show_comp_hist(bstore_t bs)
{
	bcomp_hist_iter_t pi = bstore_comp_hist_iter_new(bs);
	struct bcomp_hist_s hist, *p;
	size_t count = 0;

	hist.comp_id = comp_id;
	hist.ptn_id = ptn_id;
	hist.bin_width = bin_width;
	hist.time = begin_time;

	printf("%-12s %-24s %-12s %-12s %-12s\n",
	       "Comp Id", "Timestamp", "Pattern Id", "Bin Width (s)", "Msg Count");
	printf("------------ ------------------------ ------------ ------------ ------------\n");
	for (p = bstore_comp_hist_iter_find(pi, &hist);
	     p; p = bstore_comp_hist_iter_next(pi, &hist)) {
		struct timeval tv;

		if (end_time && hist.time > end_time)
			break;

		tv.tv_sec = hist.time;
		tv.tv_usec = 0;

		printf("%12lu %-24s %12lu %12d %12lu\n",
		       hist.comp_id,
		       fmt_date(&tv),
		       hist.ptn_id,
		       hist.bin_width,
		       hist.msg_count);
		count ++;
	}
	printf("------------ ------------------------ ------------ ------------ ------------\n");
	printf("%zu Record(s)\n", count);
}

void show_messages(bstore_t bs)
{
	bmsg_iter_t mi = bstore_msg_iter_new(bs);
	bmsg_t msg;
	btkn_id_t tkn_id;
	btkn_t tkn;

	printf("%-8s %-12s %-20s %s\n",
	       "Ptn Id", "Comp Id", "Timestamp", "Message");
	printf("-------- ------------ -------------------- --------------------\n");
	for (msg = bstore_msg_iter_find(mi, begin_time, ptn_id, comp_id, NULL, NULL);
	     msg; msg = bstore_msg_iter_next(mi)) {
		int arg;
		printf("%8lu ", msg->ptn_id);
		tkn = bstore_tkn_find_by_id(bs, msg->comp_id);
		if (tkn)
			printf("%12s ", tkn->tkn_str->cstr);
		else
			printf("%12lu ", msg->comp_id);
		printf("%-20s ", fmt_date(&msg->timestamp));
		for (arg = 0; arg < msg->argc; arg++) {
			tkn_id = msg->argv[arg] >> 8;
			btkn_type_t type_id = msg->argv[arg] & 0xFF;
			btkn_t tkn = bstore_tkn_find_by_id(bs, tkn_id);
			if (color) {
				if (type_id < BTKN_TYPE_LAST)
					printf("%s", type_colors[type_id]);
				else
					printf("%s", NORM);
			}
			printf("%s", tkn->tkn_str->cstr);
			if (color)
				printf(RESET);
			btkn_free(tkn);
		}
		printf("\n");
		bmsg_free(msg);
	}
}

void show_tokens(bstore_t bs)
{
	char types_str[80];
	btkn_iter_t ti = bstore_tkn_iter_new(bs);
	btkn_t tkn;
	printf("%-12s %-12s %-20s %s\n", "Token Id", "Count", "Types", "Text");
	printf("------------ ------------ -------------------- --------------------------------\n");
	for (tkn = bstore_tkn_iter_first(ti); tkn; tkn = bstore_tkn_iter_next(ti)) {
		int arg, i;
		if (tkn->tkn_count < min_cnt)
			goto skip;
		if (tkn_type_id && !btkn_has_type(tkn, tkn_type_id))
			goto skip;
		printf("%-12lu ", tkn->tkn_id);
		printf("%12lu ", tkn->tkn_count);
		size_t sz = 0;
		char *s = types_str;
		btkn_type_mask_t mask = tkn->tkn_type_mask;
		for (i = BTKN_TYPE_FIRST+1; i < BTKN_TYPE_LAST; i++) {
			size_t cnt;
			if (!mask)
				break;
			if (mask & BTKN_TYPE_MASK(i)) {
				mask &= ~BTKN_TYPE_MASK(i);
				if (sz) {
					*s = ' ';
					s++;
					sz++;
				}
				if (color) {
					cnt = sprintf(s, "%s", type_colors[i]);
					s += cnt;
				}
				cnt = sprintf(s, "%s", type_strs[i]);
				s += cnt;
				sz += cnt;
				if (color) {
					cnt = sprintf(s, RESET);
					s += cnt;
				}
			}
		}
		printf("%s", types_str);
		for (i = sz; i <= 20; i++)
			printf(" ");
		printf("%s\n", tkn->tkn_str->cstr);
	skip:
		btkn_free(tkn);
	}
}

#define MSG		1
#define PTN		2
#define TKN		4
#define PTNTKN		8
#define PTNHIST		16
#define TKNHIST		32
#define COMPHIST	64

#define MINUTE		60
#define HOUR		(60 * MINUTE)
#define DAY		(24 * HOUR)
#define WEEK		(7 * DAY)

int main(int argc, char *argv[])
{
	extern long timezone;
	struct tm begin_tm, end_tm;
	char *type_str = NULL;
	char *str;
	char *path = NULL;
	char *plugin = "bstore_htbl";
	int opt;
	int action = 0;
	int pos = 0;

	tzset();
	time_t t = time(0);
	localtime_r(&t, &begin_tm);
	localtime_r(&t, &end_tm);

	ptn_id = 0;
	comp_id = 0;
	bin_width = MINUTE;

	while (0 < (opt = getopt_long(argc, argv, short_opts, long_opts, NULL))) {
		switch (opt) {
		case 'W':
			if (toupper(optarg[0]) == 'M')
				bin_width = MINUTE;
			else if (toupper(optarg[0]) == 'H')
				bin_width = HOUR;
			else if (toupper(optarg[0]) == 'D')
				bin_width = DAY;
			else if (toupper(optarg[0]) == 'W')
				bin_width = WEEK;
			else
				usage(argc, argv);
			break;
		case 'B':
			str = strptime(optarg, "%F %T", &begin_tm);
			if (!str)
				usage(argc, argv);
			begin_time = mktime(&begin_tm);
			break;
		case 'E':
			str = strptime(optarg, "%F %T", &end_tm);
			if (!str)
				usage(argc, argv);
			end_time = mktime(&end_tm);
			break;
		case 's':
			path = strdup(optarg);
			break;
		case 'S':
			plugin = strdup(optarg);
			break;
		case 'p':
			action |= PTN;
			break;
		case 'P':
			ptn_id = atoi(optarg);
			break;
		case 'I':
			tkn_id = atoi(optarg);
			break;
		case 'C':
			comp_id = atoi(optarg);
			break;
		case 'm':
			action |= MSG;
			break;
		case 't':
			action |= TKN;
			break;
		case 'T':
			action |= PTNTKN;
			break;
		case '1':
			action |= PTNHIST;
			break;
		case '2':
			action |= COMPHIST;
			break;
		case '3':
			action |= TKNHIST;
			break;
		case 'A':
			pos = atoi(optarg);
			break;
		case 'c':
			color = 1;
			break;
		case 'n':
			min_cnt = strtoul(optarg, NULL, 0);
			break;
		case 'y':
			type_str = strdup(optarg);
			break;
		default:
			usage(argc, argv);
		}
	}
	if (!path)
		usage(argc, argv);
	bstore_t bs = bstore_open(plugin, path, O_RDONLY);
	if (!bs) {
		printf("The store %s could not be opened.\n", path);
		usage(argc, argv);
	}
	if (type_str) {
		btkn_t type_tkn;
		char type_name[64];
		char *s;
		for (s = type_str; *s; s++)
			*s = toupper(*s);
		/* Look it up */
		sprintf(type_name, "_%s_", type_str);
		type_tkn = bstore_tkn_find_by_name(bs, type_name, strlen(type_name)+1);
		if (!type_tkn) {
			printf("The token type %s is not valid.\n", type_str);
			usage(argc, argv);
		}
		/* The special type tokens have the special case tkn_id == tkn_type_id */
		tkn_type_id = type_tkn->tkn_id;
		btkn_free(type_tkn);
	}
	if (action & MSG)
		show_messages(bs);
	if (action & PTN)
		show_patterns(bs);
	if (action & TKN)
		show_tokens(bs);
	if (action & PTNTKN)
		show_ptn_tkns(bs, ptn_id, pos);
	if (action & PTNHIST)
		show_ptn_hist(bs);
	if (action & TKNHIST)
		show_tkn_hist(bs);
	if (action & COMPHIST)
		show_comp_hist(bs);
	return 0;
}
