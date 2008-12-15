#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include "netsummoner.h"
#include "execute.h"
#include "configuration.tab.h"

static void exec_async(const char *what) {
	pid_t pid;

	switch(pid = fork()) {
	case -1:
		printf("FORK FAILED\n");
		break;
	case 0:
		if(execlp(what, what, NULL) == -1) {
			exit(-1);
		}
		printf("Neverland\n");
		break;
	default:
		break;
	}
}

void exec_wait(void *arg) {
	int status;
	pid_t pid;
	pid = waitpid(-1, &status, WNOHANG);
	if(pid < 0) {
		return;
	}
	if(WIFEXITED(status) && !WEXITSTATUS(status)) { //Terminated with 0
		printf("Terminated normaly\n");
	} else {
		printf("Terminated abnormaly\n");
	}
}

int execute(struct action *act) {
	struct action_plan *plan;
	unsigned i;

	for(i = 0; i < act->count; i++) {
		plan = act->actions + i;
		switch(plan->type) {
		case EXECUTE:
			printf("Execute\n");
			exec_async(plan->data);
			break;
		case DHCP:
			printf("Dhcp\n");
			break;
		case EAP:
			printf("Eap\n");
			break;
		default:
			fprintf(stderr, "Unknown action type %d\n", plan->type);
			return 1;
			break;
		}
	}
	return 0;
}

