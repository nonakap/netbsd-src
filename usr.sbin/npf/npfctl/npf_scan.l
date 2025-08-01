/*-
 * Copyright (c) 2011-2025 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Martin Husemann.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

%{
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#include "npfctl.h"
#include "npf_parse.h"

int	yycolumn;

#define	YY_USER_ACTION	yycolumn += yyleng;

extern int		yystarttoken;
extern int		yylineno;
extern const char *	yyfilename;
extern int		yyparse(void);
extern void		yyrestart(FILE *);

void
npfctl_parse_file(const char *name)
{
	const bool use_stdin = strcmp(name, "-") == 0;
	FILE *fp;

	fp = use_stdin ? fdopen(STDIN_FILENO, "r") : fopen(name, "r");
	if (fp == NULL) {
		err(EXIT_FAILURE, "open '%s'", name);
	}
	yystarttoken = 0;
	yyrestart(fp);
	yylineno = 1;
	yycolumn = 0;
	yyfilename = use_stdin ? "stdin" : name;
	yyparse();
	fclose(fp);
}

void
npfctl_parse_string(const char *str, parse_entry_t entry)
{
	YY_BUFFER_STATE bs;

	switch (entry) {
	case NPFCTL_PARSE_RULE:
		yystarttoken = RULE_ENTRY_TOKEN;
		break;
	case NPFCTL_PARSE_MAP:
		yystarttoken = MAP_ENTRY_TOKEN;
		break;
	default:
		abort();
	}

	bs = yy_scan_string(str);
	yyfilename = "stdin";
	yyparse();
	yy_delete_buffer(bs);
}

%}

%option noyywrap nounput noinput

ID	[a-zA-Z_][a-zA-Z_0-9]*
DID	[a-zA-Z_][a-zA-Z_0-9-]*
SPID	[a-zA-Z][a-zA-Z_0-9.]*
NUMBER	[0-9]+
HEXDIG	[0-9a-fA-F]+

%%
%{
	/* This is prepended to yylex(). */
	if (yystarttoken) {
		int token = yystarttoken;
		yystarttoken = 0;
		return token;
	}
%}

alg			return ALG;
table			return TABLE;
type			return TYPE;
hash			return HASH;
tree			return TREE;
lpm			return LPM;
cdb			return CDB;
const			return CONST;
static			return TSTATIC;
dynamic			return TDYNAMIC;
file			return TFILE;
map			return MAP;
no-ports		return NO_PORTS;
set			return SET;
"<->"			return ARROWBOTH;
"<-"			return ARROWLEFT;
"->"			return ARROWRIGHT;
algo			return ALGO;
netmap			return NETMAP;
ipset			return IPSET;
"ip-hash"		return IPHASH;
"round-robin"		return ROUNDROBIN;
npt66			return NPT66;
"-"			return MINUS;
procedure		return PROCEDURE;
\\\n			yylineno++; yycolumn = 0;
\n			yylineno++; yycolumn = 0; return NEWLINE;
;			return SEMICOLON;
name			return NAME;
group			return GROUP;
default			return DEFAULT;
in			return IN;
out			return OUT;
forw			return FORW;
interface		return INTERFACE;
all			return ALL;
block			return BLOCK;
pass			return PASS;
pcap-filter		return PCAP_FILTER;
stateful		return STATEFUL;
stateful-all		return STATEFUL_ALL;
apply			return APPLY;
final			return FINAL;
quick			return FINAL;
on			return ON;
off			return OFF;
inet6			return INET6;
inet4			return INET4;
ifaddrs			return IFADDRS;
proto			return PROTO;
family			return FAMILY;
tcp			return TCP;
icmp			{ yylval.num = IPPROTO_ICMP; return ICMP; }
ipv6-icmp		{ yylval.num = IPPROTO_ICMPV6; return ICMP6; }
\"ipv6-icmp\"		{ yylval.num = IPPROTO_ICMPV6; return ICMP6; }
return-rst		return RETURNRST;
return-icmp		return RETURNICMP;
return			return RETURN;
ruleset			return RULESET;
from			return FROM;
to			return TO;
port			return PORT;
flags			return FLAGS;
icmp-type		return ICMPTYPE;
code			return CODE;
any			return ANY;
user			return USER;
ether			return ETHER;
layer-2			return L2;

"/"			return SLASH;
"{"			return CURLY_OPEN;
"}"			return CURLY_CLOSE;
"("			return PAR_OPEN;
")"			return PAR_CLOSE;
","			return COMMA;
"="			return EQ;
"!"			return EXCL_MARK;
"<"			return LT;
">"			return GT;
"<>"			return XRG;
"><"			return IRG;

"0x"{HEXDIG} {
			char *endp, *buf = ecalloc(1, yyleng + 1);
			buf[yyleng] = 0;
			yylval.num = strtoul(buf+2, &endp, 16);
			free(buf);
			return HEX;
		}

"Ex"{HEXDIG} {
			yylval.str = estrndup(yytext, yyleng);
			return ETHERHEX;
		}

{NUMBER}"."{NUMBER} {
			char *endp, *buf = estrndup(yytext, yyleng);
			yylval.fpnum = strtod(buf, &endp);
			free(buf);
			return FPNUM;
		}

{HEXDIG}(":"{HEXDIG}){5} {
			yylval.str = estrndup(yytext, yyleng);
			return MACADDR;
		}

{HEXDIG}":"[0-9a-fA-F:]* {
			yylval.str = estrndup(yytext, yyleng);
			return IPV6ADDR;
		}

"::"{HEXDIG}[0-9a-fA-F:.]* {
			yylval.str = estrndup(yytext, yyleng);
			return IPV6ADDR;
		}

{NUMBER}"."[0-9][0-9.]* {
			yylval.str = estrndup(yytext, yyleng);
			return IPV4ADDR;
		}

{NUMBER}	{
			char *endp, *buf = estrndup(yytext, yyleng);
			yylval.num = strtoul(buf, &endp, 10);
			free(buf);
			return NUM;
		}

"<"{DID}">"	{
			yylval.str = estrndup(yytext + 1, yyleng - 2);
			return TABLE_ID;
		}

"$"{ID}		{
			yylval.str = estrndup(yytext + 1, yyleng - 1);
			return VAR_ID;
		}

{ID}"."{SPID}+	{
			yylval.str = estrndup(yytext, yyleng);
			return PARAM;
		}

{ID}		{
			yylval.str = estrndup(yytext, yyleng);
			return IDENTIFIER;
		}

\"[^\"]*\"	{
			yylval.str = estrndup(yytext + 1, yyleng - 2);
			return STRING;
		}

#.*$		/* drop comment until end of line */
[ \t]		/* eat whitespace */

:		return COLON;

.		return INVALID;
