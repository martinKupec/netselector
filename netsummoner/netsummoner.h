#ifndef __NETSUMMONER_NETSUMMONER_H__
#define __NETSUMMONER_NETSUMMONER_H__

#include <stdbool.h>
#include <stdint.h>

#include "lib/list.h"
#include "lib/netselector.h"

struct rule {
	bool matched;
	int type;
	void *data;
};

struct rule_set {
	unsigned matched;
	int type;
	unsigned score;
	unsigned count;
	struct rule *items;
};

struct network {
	unsigned count;
	struct rule_set *rules;
	char *name;
	unsigned target_score;
};

struct action_plan {
	int type;
	void *data;
};

struct action {
	char *name;
	unsigned count;
	struct action_plan *actions;
};

struct arbiter_queue {
	struct stat_ether *enode_f, *enode_t;
	struct stat_ip *inode_f, *inode_t;
	struct stat_wifi *wnode;
};

struct combination {
	int condition;
	void *condition_args;
	struct action *up;
	bool down_reversed;
	struct action *down;
	bool active;
};

struct assembly {
	char *name;
	struct network *net;
	unsigned count;
	struct combination *comb;
};

extern struct list list_network, list_action, list_assembly;

//Structures for yacc
struct assembly_combination { 
	char *network;
	unsigned count;
	struct combination *comb;
};

struct rev_action {
	struct action *action;
	bool rev;
};

struct rule_ret {
	struct rule *items;
	unsigned count;
};

#endif
