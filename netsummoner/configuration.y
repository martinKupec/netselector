%{
#include <stdio.h>

#include "netsummoner.h"

int yylex(void);
extern char const *yytext;
void yyerror (char const *err);
unsigned rule_count;

struct rule_ret {
	struct rule *items;
	unsigned count;
	int type;
};

%}

%locations

%union {
	char const *str;
	int num;
	struct network *network;
	struct action *action;
	struct assembly *assembly;
	struct rule_ret rule_ret;
}

%token <num> VAL_NUM
%token <str> VAL_STR VAL_IP VAL_MAC
%token <str> NETWORK ACTION ASSEMBLY
%token <str> WIFI STP GATEWAY DHCPS NBNS EAP WLCCP CDP DNS
%token <str> MAC ESSID NAME IP ROOT 
%token <str> DHCP ID EXECUTE NOT USE MATCH DOWN ON

%type <rule_set> nstmt
%type <rule_ret> wifi
%type <network> network
%type <action> action
%type <assembly> assembly

%%

config: /* empty */
	| decl config
	;

decl: network { list_network_add($1); }
	| action { list_action_add($1); }
	| assembly { list_assembly_add($1); }
	;

network: NETWORK VAL_STR VAL_NUM { rule_count = 0; } '{' nstmt '}' { $$ = new_network($2, $3, $6); }
	;

nstmt: /* empty */ { $$ = malloc(sizeof(struct rule) * rule_count); rule_count--; }
	| WIFI wifi nstmtn
	| STP stp nstmtn
	| GATEWAY gateway nstmtn
	| DHCPS dhcps nstmtn
	| NBNS nbns nstmtn
	| EAP eap nstmtn
	| WLCCP wlccp nstmtn
	| CDP cdp nstmtn
	| DNS dns nstmtn
	;
nstmtn: VAL_NUM { rule_count++; } nstmt { $3[rule_count].score = $1; $[rule_count].matched = 0;
			$3[rule_count].type = $0.type; $3[rule_count].rules = $0.items; $3[rule_count].count = $0.count; rule_count--; }
	;

wifi: mac { $$.count = 1; $$.items = malloc(sizeof(struct rule)); $$.items.type = $1.type; $$.items.data = $1.data; }
	| essid { $$.count = 1; $$.items = malloc(sizeof(struct rule)); $$.items.type = $1.type; $$.items.data = $1.data; }
	| mac essid
	| essid mac
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

essid: ESSID VAL_STR
	| NOT ESSID VAL_STR
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
	//fprintf(stderr, "Bison: %s ", err);
	fprintf(stderr, "Unexpected symbol %s at line %d\n", yytext, yylloc.first_line);
}

