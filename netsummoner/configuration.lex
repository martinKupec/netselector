%{
#define YY_NO_UNPUT 1
#include "configuration.tab.h"
#include <stdlib.h>
#define YY_USER_ACTION yylval.str = yytext;
%}

%option batch
%option 8bit
%option yylineno
%option ecs
%option noyywrap

%%
"network"		{ return NETWORK; }
"action"		{ return ACTION; }
"assembly"		{ return ASSEMBLY; }
"wifi"			{ return WIFI; }
"stp"			{ return STP; }
"dhcps"			{ return DHCPS; }
"nbns"			{ return NBNS; }
"gateway"		{ return GATEWAY; }
"eap"			{ return EAP; }
"wlccp"			{ return WLCCP; }
"cdp"			{ return CDP; }
"dns"			{ return DNS; }
"ip"			{ return IP; }
"root"			{ return ROOT; }
"mac"			{ return MAC; }
"essid"			{ return ESSID; }
"dhcp"			{ return DHCP; }
"name"			{ return NAME; }
"id"			{ return ID; }
"execute"		{ return EXECUTE; }
"not"			{ return NOT; }
"use"			{ return USE; }
"on"			{ return ON; }
"match"			{ return MATCH; }
"down"			{ return DOWN; }
([[:digit:]]+\.){3}[[:digit:]]+	{ return VAL_IP; }
([a-fA-F0-9]+:)+[a-fA-F0-9]+	{ return VAL_MAC; }
[[:digit:]]+	{ yylval.num = atoi(yytext); return VAL_NUM; }
\"[[:alnum:]_/\.-]*\"	{ return VAL_STR; }
"{"|"}"				{ return yytext[0]; }
#.*			/* Comments falls througth */
\n|\ |\t	/* New lines and such falls througth */
.		{ printf("Not token \"%s\"\n", yytext); return -1; }

%%

