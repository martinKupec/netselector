%{
#include <stdio.h>

#define YYERROR_VERBOSE 1

int yylex(void);
void yyerror (char const *err);

%}

%union {
	char const *str;
	int num;
}

%token <str> VAL_STR VAL_IP VAL_MAC
%token <num> VAL_NUM
%token <str> NETWORK ACTION ASSEMBLY STRING WIFI STP GATEWAY DHCPS NBNS
%token <str> MAC ESSID DNS NAME CDP IP ROOT WLCCP EAP
%token <str> DHCP ID EXECUTE NOT USE MATCH DOWN ON

%%

config: /* empty */
	| decl config
	;

decl: network
	| action
	| assembly
	;

network: NETWORK VAL_STR VAL_NUM '{' nstmt '}'
	;

nstmt: /* empty */
	| WIFI wifi VAL_NUM nstmt
	| STP stp VAL_NUM nstmt
	| GATEWAY gateway VAL_NUM nstmt
	| DHCPS dhcps VAL_NUM nstmt
	| NBNS nbns VAL_NUM nstmt
	| EAP eap VAL_NUM nstmt
	| WLCCP wlccp VAL_NUM nstmt
	| CDP cdp VAL_NUM nstmt
	| DNS dns VAL_NUM nstmt
	;

wifi: mac
	| ESSID VAL_STR
	| mac ESSID VAL_STR
	| ESSID VAL_STR mac
	;

stp: ROOT VAL_MAC
	;

gateway: ip
	|    mac
	|    ip mac
	|	 mac ip
	;

dhcps: ip
	|  mac
	|  ip mac
	|  mac ip
	;

nbns: NAME VAL_STR
	;

eap: mac
	;

wlccp: mac
	;

cdp: ID VAL_STR
	;

dns: ip
	;

mac: MAC VAL_MAC
	| NOT MAC VAL_MAC
	;
ip: IP VAL_IP
	| NOT IP VAL_IP
	;

action: ACTION VAL_STR '{' astmt '}'
	;

astmt: /* empty*/
	| execute astmt
	| use astmt
	;

execute: EXECUTE VAL_STR
	;

use: USE DHCP
	| USE EAP VAL_STR
	;

assembly: ASSEMBLY VAL_STR ON MATCH VAL_STR
	|	ASSEMBLY VAL_STR ON DOWN VAL_STR
	;
%%

void yyerror (char const *err) {
	fprintf(stderr, "Bison: %s\n", err);
}

