#ifndef __NETSUMMONER_EXECUTE_H__
#define __NETSUMMONER_EXECUTE_H__

#include "netsummoner.h"

enum {
	EXEC_MATCH,
	EXEC_DOWN,
};

int execute(struct network *net, unsigned action);

#endif
