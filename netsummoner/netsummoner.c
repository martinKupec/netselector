#include <stdio.h>

#include "netsummoner.h"
#include "list.h"

struct list list_network;

int yyparse(void);

static void daemonize(void) {

}

int main(int argc, char **argv) {
	
	list_init(&list_network);
	daemonize();
	yyparse();
	return 0;
}

