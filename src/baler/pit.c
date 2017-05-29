/* -*- c-basic-offset: 8 -*- */
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <assert.h>

#include "bcommon.h"
#include "btypes.h"
#include "butils.h"
#include "bmapper.h"
#include "binput_private.h"
#include "boutput.h"
#include "btkn.h"
#include "bptn.h"
#include "bwqueue.h"

binp_parser_t loadit(char *lib)
{
	binp_get_parser_fn_t get_parser;
	void *d = dlopen(lib, RTLD_NOW);
	if (!d) {
		printf("%s", dlerror());
		return NULL;
	}
	get_parser = dlsym(d, "binp_get_parser");
	if (!get_parser) {
		printf("This is not a parser plugin.\n");
		return NULL;
	}
	binp_parser_t p = get_parser(d);
	if (!p) {
		printf("Insufficient resources\n");
		return NULL;
	}
	return p;

}

#define OPTS "p:f:v"
void usage(int argc, char **argv)
{
	printf("usage: %s -p <plugin_path> [ -f <input> ]\n"
	       "       -p <plugin_path> Mandatory path to the plugin\n"
	       "       -f <input>       Optional input file, defaults to stdin.\n",
	       argv[0]);
	exit(1);
}

#define LINE_BUF_LEN 4096
int main(int argc, char **argv)
{
	char *line, *buffer;
	FILE *input = stdin;
	char *plugin_path = NULL;
	int c;
	int verbose = 0;
	int rc = 0;
	while (0 < (c = getopt(argc, argv, OPTS))) {
		switch (c) {
		case 'p':
			plugin_path = strdup(optarg);
			break;
		case 'f':
			input = fopen(optarg, "r");
			if (!input) {
				printf("Could not open the input file %s, error %d\n",
				       optarg, errno);
				usage(argc, argv);
			}
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage(argc, argv);
		}
	}
	if (!plugin_path)
		usage(argc, argv);
	binp_parser_t parser = loadit(plugin_path);
	free(plugin_path);
	if (!parser)
		goto out;
	buffer = malloc(LINE_BUF_LEN);
	if (!buffer)
		goto enomem;
	while (NULL != (line = fgets(buffer, LINE_BUF_LEN, input))) {
		binp_result_t res;
		bwq_entry_t wqe;
		btkn_tailq_entry_t e;
		struct bstr *str = bstr_alloc_init_cstr(line);
		if (!str)
			goto enomem;
		wqe = NULL;
		res = parser->parse(parser, str, &wqe);
		if (res) {
			printf("SYNTAX ERROR: %s", line);
			rc = EINVAL;
			break;
		}
		bstr_free(str);
		if (!wqe)
			continue;
		if (verbose) {
			puts(line);
			if (wqe->data.in.hostname)
				printf("%s ", wqe->data.in.hostname->cstr);
			TAILQ_FOREACH(e, &(wqe->data.in.tkn_q), link) {
				const char *type_str = ptn_type_strs[btkn_first_type(e->tkn)];
				if (type_str)
					printf("    %-8s : '%s'\n",
					       type_str,
					       e->tkn->tkn_str->cstr);
				else
					printf("    %-8d : '%s'\n",
					       btkn_first_type(e->tkn),
					       e->tkn->tkn_str->cstr);
			}
		}
		btkn_tailq_free_entries(&(wqe->data.in.tkn_q));
		free(wqe);
	}
	free(buffer);
	parser->release(parser);
 out:
	return rc;
 enomem:
	printf("Memory allocation failure.\n");
	return 2;
}
