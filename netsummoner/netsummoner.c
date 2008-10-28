#include <stdio.h>

int yyparse(void);

static void daemonize(void) {

}

int main(int argc, char **argv) {
	
	daemonize();
	yyparse();
	return 0;
}

