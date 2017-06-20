#include <assert.h>
#include <stdio.h>
#include <getopt.h>
#include <fcntl.h>

#include <baler/bmeta.h>
#include <baler/butils.h>

const char *short_opts = "P:p:D:S:L:?";

const struct option long_opts[] = {
	{"plugin",      1,  0,  'P'},
	{"path",        1,  0,  'p'},
	{"diff-ratio",  1,  0,  'D'},
	{"speed",       1,  0,  'S'},
	{"looseness",   1,  0,  'L'},
	{0,             0,  0,  0},
};

const char *plugin = "bstore_sos";
const char *path = NULL;

struct bmc_params_s bmc_params = {
			.diff_ratio = 0.15,
			.refinement_speed = 2.0,
			.looseness = 0.15,
		};

void usage()
{
	printf(
"	Usage: bmeta_test \n"
"		-p,--path STORE_PATH\n"
"		-P,--plugin STORE_PLUGIN\n"
"		-D,--diff-ratio DIFF_RATIO(0.0 - 1.0)\n"
"		-S,--speed DIFF_RATIO(1.0 - inf)\n"
"		-L,--looseness LOOSENESS(0.0 - 1.0)\n"
	);
}

void handle_args(int argc, char **argv)
{
	char c;
loop:
	c = getopt_long(argc, argv, short_opts, long_opts, NULL);
	switch (c) {
	case -1:
		goto out;
	case 'P':
		plugin = optarg;
		break;
	case 'p':
		path = optarg;
		break;
	case 'D':
		bmc_params.diff_ratio = atof(optarg);
		break;
	case 'S':
		bmc_params.refinement_speed = atof(optarg);
		break;
	case 'L':
		bmc_params.looseness = atof(optarg);
		break;
	default:
		usage();
		exit(0);
	}
	goto loop;
out:
	/* check store */
	if (!path) {
		berr("-p,--path is required");
		exit(-1);
	}
	return;
}

void print_ptn(bstore_t bs, bptn_t ptn)
{
	btkn_id_t tkn_id;
	int len = ptn->str->blen / sizeof(btkn_id_t);
	int i;
	btkn_t tkn;
	for (i = 0; i < len; i++) {
		tkn_id = ptn->str->u64str[i] >> 8;
		// assert(i || tkn_id == BTKN_TYPE_HOSTNAME);
		tkn = bstore_tkn_find_by_id(bs, tkn_id);
		assert(tkn);
		printf("%.*s", tkn->tkn_str->blen, tkn->tkn_str->cstr);
		btkn_free(tkn);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	handle_args(argc, argv);
	binfo("plugin: %s", plugin);
	binfo("path: %s", path);
	binfo("diff-ratio: %f", bmc_params.diff_ratio);
	binfo("speed: %f", bmc_params.refinement_speed);
	binfo("looseness: %f", bmc_params.looseness);

	bstore_t bs = bstore_open(plugin, path, O_RDWR);
	assert(bs);

	bmc_list_t bmc_list = bmc_list_compute(bs, &bmc_params);
	assert(bmc_list);

	bmc_t bmc;
	BMC_LIST_FOREACH(bmc, bmc_list) {
		print_ptn(bs, bmc->meta_ptn);
	}

	bmc_list_free(bmc_list);

	return 0;
}
