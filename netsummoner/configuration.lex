%{
#include "tokens.h"
%}

%option batch
%option 8bit
%option yylineno
%option ecs
%option noyywrap

%%
"network"		|
"action"		|
"wifi"			|
"stp"			|
"root"			|
"mac"			|
"essid"			|
"dhcps"			|
"dhcp"			|
"nbns"			|
"name"			|
"gateway"		|
"ip"			|
"eap"			|
"dns"			|
"wlccp"			|
"cdp"			|
"id"			|
"execute"		|
"not"			|
"use"			|
"assembly"		|
"on"			|
"match"			|
"down"			|
"{"				|
"}"				|
([[:digit:]]+\.){3}[[:digit:]]+	|
([a-fA-F0-9]+:)+[a-fA-F0-9]+	|
[[:digit:]]*	|
\"[[:alnum:]_/\.-]*\"	|
	/*
#.*			{ printf("Token \"%s\"\n", yytext); return 1; }
	*/
#.*			{ return 1; }
\n|\ |\t	{ }
.		{ printf("Not token \"%s\"\n", yytext); return 2; }

%%

