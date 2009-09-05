#ifndef __NETSUMMONER_EXECUTE_H__
#define __NETSUMMONER_EXECUTE_H__

#include "netsummoner.h"

enum {
	EXEC_MATCH,
	EXEC_DOWN,
	EXEC_RESTART,
};

int execute_running(void);
void execute_close_on_connect(bool close);
int execute(struct network *net, unsigned action);

#endif
