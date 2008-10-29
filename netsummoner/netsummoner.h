#ifndef __NETSUMMONER_H__
#define __NETSUMMONER_H__

#include <stdbool.h>
#include <stdint.h>

#include "list.h"

extern struct list list_network;

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
	bool matched;
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

#endif
