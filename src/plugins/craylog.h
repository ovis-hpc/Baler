#ifndef __SYSLOG_H__
#define __SYSLOG_H__

#include <sys/time.h>
#include <inttypes.h>
#include <baler/bplugin.h>
#include <baler/bwqueue.h>

enum craylog_parser_state {
	STATE_START = 0,
	STATE_EOL,
	STATE_EOF,
	STATE_ERROR,
};
typedef struct craylog_parser {
	struct binp_parser base;
	enum craylog_parser_state state;
	int cpos;		/* character position */
	struct bstr *input;	/* current input string */
	struct yy_buffer_state *buffer_state;
} *craylog_parser_t;

#define YYSTYPE btkn_t


/* User-defined token types for the Cray syslog parser */
#define BTKN_TYPE_ASIC_RTR_NODE	32
#define BTKN_TYPE_ASIC_RTR_LINK	33
#define BTKN_TYPE_DEC_LIST	34
#define BTKN_TYPE_HEX_DUMP	35
#define BTKN_TYPE_CHAR_DUMP	36

#endif
