#include <stdio.h>

#include "netsummoner.h"
#include "list.h"

struct list list_network, list_action, list_assembly;

int yyparse(void);

static void daemonize(void) {

}

int main(int argc, char **argv) {
	
	list_init(&list_network);
	list_init(&list_action);
	list_init(&list_assembly);
	daemonize();
	yyparse();
	return 0;
}

