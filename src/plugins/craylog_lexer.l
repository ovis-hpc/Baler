%{
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#define YYSVAL token_t
#include "craylog.h"
#include "craylog_parser.h"

#define YY_DECL int yylex(YYSTYPE *lvalp, craylog_parser_t parser, struct bstr *msg_buf)
#define YY_USER_ACTION parser->cpos += yyleng;

int token_alloc(int type_id, const char *yytext, size_t yyleng, YYSTYPE *lvalp)
{
	assert(yyleng);
	btkn_t tkn = btkn_alloc(0, 0, yytext, yyleng);
	if (!tkn)
		return 0;
	*lvalp = tkn;
	return type_id;
}

%}

BSD_SVC			"["[A-Za-z_\-]+("."[A-Za-z_\-]+)*":"[A-Za-z_\-]+"]"
PATH			(\/[[:alnum:]_\-~.]+)+
/* Text may contain embedded '.', '-', and '_', but will not match trailing '.' */
CRAY_RTR_LINK		c[[:digit:]]+\-[[:digit:]]+c[[:digit:]]+s[[:digit:]]+[ag][[:digit:]]+l[[:digit:]]+
CRAY_RTR_NODE		(c[[:digit:]]+-[[:digit:]]+)(c[[:digit:]]+){1}(s[[:digit:]]+){1}(ag][[:digit:]]+[n][[:digit:]]+){1}
CRAY_HOST		(c[[:digit:]]+-[[:digit:]]+)(c[[:digit:]]+){1}(s[[:digit:]]+){1}(n[[:digit:]]+)
CRAY_SLOT		(c[[:digit:]]+-[[:digit:]]+)(c[[:digit:]]+){1}(s[[:digit:]]+){1}
CRAY_NID		(nid[[:digit:]]{2})([[:digit:]]+)
TEXT			([[:alpha:]]+)|([[:alpha:]_]+([[:alnum:]\-_.]+)?([[:alnum:]\-_]+))
IP4_ADDR		[[:digit:]]{1,3}\056[[:digit:]]{1,3}\056[[:digit:]]{1,3}\056[[:digit:]]{1,3}("/"[0-9]{1,2})?
IP6_ADDR		([[:xdigit:]]{1,4})?:([[:xdigit:]]{1,4})?:([[:xdigit:]]{1,4})?:([[:xdigit:]]{1,4})?:([[:xdigit:]]{1,4})?:[[:xdigit:]]{1,4}("/"[0-9]{1,3})?
CRAY_SLOT_LIST		{CRAY_SLOT}([ ,]{CRAY_SLOT})+
CRAY_HOST_LIST		{CRAY_HOST}([ ,]{CRAY_HOST})+
CRAY_RTR_LIST		({CRAY_RTR_NODE}|{CRAY_RTR_LINK})([ ,]({CRAY_RTR_NODE}|{CRAY_RTR_LINK}))+
NID_LIST		([[:space:]]+[[:digit:]]+":")([[:space:]]*[[:digit:]]+":")+
HASH_LIST		("#"[[:digit:]]{3})("#"[[:digit:]]{3})+
DEC_LIST		(({DEC_INT})|({DEC_INT}"-"{DEC_INT}))(","(({DEC_INT})|({DEC_INT}"-"{DEC_INT})))+
HEX_DUMP		[[:xdigit:]]{2}((" ")+[[:xdigit:]]{2})+
CHAR_DUMP		"*"[^[:space:]]{2}[^[:space:]]+"*"
MAC_ADDR		[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}
HEX_INT			(0[xX])?[[:xdigit:]]+
DEC_INT			[[:digit:]]+
FLOAT			[[:digit:]]+"."[[:digit:]]*([eE][[:digit:]]+"."[[:digit:]]*)?
TIMESTAMP		[[:digit:]]{4}"-"[[:digit:]]{2}"-"[[:digit:]]{2}"T"[[:digit:]]{2}":"[[:digit:]]{2}":"[[:digit:]]{2}("."[[:digit:]]+)?(([+-][[:digit:]]{2}":"[[:digit:]]{2})|"Z")
TIMESTAMP2		(("Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec")(" ")+[[:digit:]]{1,2}(",")?(" ")+([[:digit:]]{4}(" ")+)?[[:digit:]]{2}":"[[:digit:]]{2}":"[[:digit:]]{2})
TIMESTAMP3		[[:digit:]]{4}"-"[[:digit:]]{2}"-"[[:digit:]]{2}" "[[:digit:]]{2}":"[[:digit:]]{2}":"[[:digit:]]{2}
HTTP			[hH][tT]{2}[pP]([sS])?:\/\/

%option noyywrap

%%
	if (!parser->buffer_state) {
		int i;
		msg_buf->cstr[msg_buf->blen] = '\0';
		if (msg_buf->cstr[msg_buf->blen-1] == '\n')
			msg_buf->cstr[msg_buf->blen-1] = '\0';
		for (i = 0; i < msg_buf->blen; i++) {
			if (msg_buf->cstr[i] == '\0')
				break;
			if (!isprint(msg_buf->cstr[i])
			    || ((unsigned char)msg_buf->cstr[i] > 0x7f))
				msg_buf->cstr[i] = 'X';
		}
		parser->buffer_state = yy_scan_string(msg_buf->cstr);
		parser->cpos = 0;
	}

<<EOF>>	{
	yy_delete_buffer(parser->buffer_state);
	parser->buffer_state = NULL;
	return 0;
	}

{CRAY_HOST} {
	return token_alloc(HOSTNAME_TKN, yytext, yyleng, lvalp);
	}

{CRAY_HOST_LIST} {
	return token_alloc(CRAY_HOST_LIST_TKN, yytext, yyleng, lvalp);
	}

{CRAY_NID} {
	return token_alloc(CRAY_NID_TKN, yytext, yyleng, lvalp);
	}

{CRAY_SLOT} {
	return token_alloc(CRAY_SLOT_TKN, yytext, yyleng, lvalp);
}

{CRAY_SLOT_LIST} {
	return token_alloc(CRAY_SLOT_LIST_TKN, yytext, yyleng, lvalp);
}

{CRAY_RTR_NODE} {
	return token_alloc(CRAY_RTR_NODE_TKN, yytext, yyleng, lvalp);
	}

{CRAY_RTR_LINK} {
	return token_alloc(CRAY_RTR_LINK_TKN, yytext, yyleng, lvalp);
	}

{CRAY_RTR_LIST} {
	return token_alloc(CRAY_RTR_LIST_TKN, yytext, yyleng, lvalp);
	}

{NID_LIST} {
	return token_alloc(NID_LIST_TKN, yytext, yyleng, lvalp);
	}

{HASH_LIST} {
	return token_alloc(HASH_LIST_TKN, yytext, yyleng, lvalp);
	}

{CHAR_DUMP} {
	return token_alloc(CHAR_DUMP_TKN, yytext, yyleng, lvalp);
	}

{HEX_DUMP} {
	return token_alloc(HEX_DUMP_TKN, yytext, yyleng, lvalp);
	}

{DEC_LIST} {
	return token_alloc(DEC_LIST_TKN, yytext, yyleng, lvalp);
	}

{MAC_ADDR} {
	return token_alloc(ETH_ADDR_TKN, yytext, yyleng, lvalp);
	}
^\<[[:digit:]]+\> {
	return token_alloc(PRIORITY_TKN, yytext, yyleng, lvalp);
	}
{IP4_ADDR} {
	return token_alloc(IP4_ADDR_TKN, yytext, yyleng, lvalp);
	}
{IP6_ADDR} {
	return token_alloc(IP6_ADDR_TKN, yytext, yyleng, lvalp);
	}
{DEC_INT} {
	return token_alloc(DEC_INT_TKN, yytext, yyleng, lvalp);
	}
{HEX_INT} {
	return token_alloc(HEX_INT_TKN, yytext, yyleng, lvalp);
	}
{FLOAT}	{
	return token_alloc(FLOAT_TKN, yytext, yyleng, lvalp);
	}
{PATH}	{
	return token_alloc(PATH_TKN, yytext, yyleng, lvalp);
	}
{HTTP}{TEXT}(\/{TEXT})*\/?	{
	return token_alloc(URL_TKN, yytext, yyleng, lvalp);
	}
{TIMESTAMP} {
	return token_alloc(TIMESTAMP_TKN, yytext, yyleng, lvalp);
	}
{TIMESTAMP2} {
	return token_alloc(TIMESTAMP_TKN, yytext, yyleng, lvalp);
	}
{TIMESTAMP3} {
	return token_alloc(TIMESTAMP_TKN, yytext, yyleng, lvalp);
	}

{BSD_SVC} {
	return token_alloc(BSD_SVC_TKN, yytext, yyleng, lvalp);
	}

{TEXT} {
	return token_alloc(TEXT_TKN, yytext, yyleng, lvalp);
	}

[[^:alnum:]]|[[:punct:]] {
	return token_alloc(SEPARATOR_TKN, yytext, yyleng, lvalp);
	}
[[:space:]]+ {
	return token_alloc(WHITESPACE_TKN, yytext, yyleng, lvalp);
	}
