%{
#include <stdlib.h>
#include "netsummoner/netsummoner.h"
#include "netsummoner/configuration.tab.h"

#define YY_NO_UNPUT 1
#define YY_USER_ACTION yylloc.first_line = yylineno;
%}

%option batch
%option 8bit
%option yylineno
%option ecs
%option noyywrap

%%
"network"		{ yylval.num = NETWORK; return NETWORK; }
"action"		{ yylval.num = ACTION; return ACTION; }
"assembly"		{ yylval.num = ASSEMBLY; return ASSEMBLY; }
"wifi"			{ yylval.num = WIFI; return WIFI; }
"stp"			{ yylval.num = STP; return STP; }
"dhcps"			{ yylval.num = DHCPS; return DHCPS; }
"nbns"			{ yylval.num = NBNS; return NBNS; }
"gateway"		{ yylval.num = GATEWAY; return GATEWAY; }
"eap"			{ yylval.num = EAP; return EAP; }
"wlccp"			{ yylval.num = WLCCP; return WLCCP; }
"cdp"			{ yylval.num = CDP; return CDP; }
"dns"			{ yylval.num = DNS; return DNS; }
"ip"			{ yylval.num = IP; return IP; }
"root"			{ yylval.num = ROOT; return ROOT; }
"mac"			{ yylval.num = MAC; return MAC; }
"essid"			{ yylval.num = ESSID; return ESSID; }
"dhcp"			{ yylval.num = DHCP; return DHCP; }
"name"			{ yylval.num = NAME; return NAME; }
"id"			{ yylval.num = ID; return ID; }
"execute"		{ yylval.num = EXECUTE; return EXECUTE; }
"not"			{ yylval.num = NOT; return NOT; }
"use"			{ yylval.num = USE; return USE; }
"on"			{ yylval.num = ON; return ON; }
"match"			{ yylval.num = MATCH; return MATCH; }
"down"			{ yylval.num = DOWN; return DOWN; }
([[:digit:]]+\.){3}[[:digit:]]+	{ yylval.str = strdup(yytext); return VAL_IP; }
([a-fA-F0-9]+:)+[a-fA-F0-9]+	{ yylval.str = strdup(yytext); return VAL_MAC; }
[[:digit:]]+	{ yylval.num = atoi(yytext); return VAL_NUM; }
\"[[:alnum:]_/\.-]*\"	{ yylval.str = strdup(yytext + 1); yylval.str[strlen(yylval.str) - 1] = '\0'; return VAL_STR; }
"{"|"}"				{ return yytext[0]; }
#[^\n]*			/* Comments falls througth */
\n|\ |\t	/* New lines and such falls througth */
.		{ return -2; }

%%

