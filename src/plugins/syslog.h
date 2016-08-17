#ifndef __SYSLOG_H__
#define __SYSLOG_H__

#include <sys/time.h>
#include <inttypes.h>
#include <baler/bplugin.h>
#include <baler/bwqueue.h>

enum syslog_parser_state {
	STATE_START = 0,
	STATE_EOL,
	STATE_EOF,
	STATE_ERROR,
};
typedef struct syslog_parser {
	struct binp_parser base;
	enum syslog_parser_state state;
	int cpos;		/* character position */
	struct bstr *input;	/* current input string */
	struct yy_buffer_state *buffer_state;
} *syslog_parser_t;

#define YYSTYPE btkn_t

#endif
