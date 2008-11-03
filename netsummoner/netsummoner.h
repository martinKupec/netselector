#ifndef __NETSUMMONER_NETSUMMONER_H__
#define __NETSUMMONER_NETSUMMONER_H__

#include <stdbool.h>
#include <stdint.h>

#include "list.h"

struct rule {
	bool matched;
	int type;
	void *data;
};

struct rule_ret {
	struct rule *items;
	unsigned count;
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

struct assembly {
	int type;
	char *net_name;
	char *act_name;
};

extern struct list list_network, list_action, list_assembly;

#endif
