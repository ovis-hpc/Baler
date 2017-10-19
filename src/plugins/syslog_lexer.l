%{
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#define YYSVAL token_t
#include "syslog.h"
#include "syslog_parser.h"

#define YY_DECL int yylex(YYSTYPE *lvalp, syslog_parser_t parser, struct bstr *msg_buf)
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
TEXT			([[:alpha:]]+)|([[:alpha:]_]+([[:alnum:]\-_.]+)?([[:alnum:]\-_]+))
IP4_ADDR		[[:digit:]]{1,3}\056[[:digit:]]{1,3}\056[[:digit:]]{1,3}\056[[:digit:]]{1,3}("/"[0-9]{1,2})?
IP6_ADDR		([[:xdigit:]]{1,4})?:([[:xdigit:]]{1,4})?:([[:xdigit:]]{1,4})?:([[:xdigit:]]{1,4})?:([[:xdigit:]]{1,4})?:[[:xdigit:]]{1,4}("/"[0-9]{1,3})?
MAC_ADDR		[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}
HEX_INT			(0[xX])?[[:xdigit:]]+
DEC_INT			[[:digit:]]+
FLOAT			[[:digit:]]+"."[[:digit:]]*([eE][[:digit:]]+"."[[:digit:]]*)?
TIMESTAMP		[[:digit:]]{4}"-"[[:digit:]]{2}"-"[[:digit:]]{2}"T"[[:digit:]]{2}":"[[:digit:]]{2}":"[[:digit:]]{2}("."[[:digit:]]+)?[+-](([[:digit:]]{2}":"[[:digit:]]{2})|([[:digit:]]+[tT][[:digit:]]+))
TIMESTAMP2		(("Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec")(" ")+[[:digit:]]{1,2}(",")?(" ")+([[:digit:]]{4}(" ")+)?[[:digit:]]{2}":"[[:digit:]]{2}":"[[:digit:]]{2})
TIMESTAMP3		[[:digit:]]{4}"-"[[:digit:]]{2}"-"[[:digit:]]{2}" "[[:digit:]]{2}":"[[:digit:]]{2}":"[[:digit:]]{2}
HTTP			[hH][tT]{2}[pP]([sS])?:\/\/

%%

	if (!parser->buffer_state) {
		if (msg_buf->cstr[msg_buf->blen-1] == '\n')
			msg_buf->cstr[msg_buf->blen-1] = '\0';
		parser->buffer_state = yy_scan_string(msg_buf->cstr);
		parser->cpos = 0;
	}

<<EOF>>	{
	yy_delete_buffer(parser->buffer_state);
	parser->buffer_state = NULL;
	return 0;
	}

[\n]	{ printf("Newline in input string!\n"); return 0; }

{MAC_ADDR} {
	return token_alloc(ETH_ADDR_TKN, yytext, yyleng, lvalp);
	}
^\<[[:digit:]]+\> {
	return token_alloc(PRIORITY_TKN, yytext, yyleng, lvalp);
	}

{TEXT} {
	return token_alloc(TEXT_TKN, yytext, yyleng, lvalp);
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

[[^:alnum:]]|[[:punct:]] {
	return token_alloc(SEPARATOR_TKN, yytext, yyleng, lvalp);
	}
[[:space:]]+ {
	return token_alloc(WHITESPACE_TKN, yytext, yyleng, lvalp);
	}
