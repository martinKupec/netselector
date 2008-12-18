#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "netsummoner.h"
#include "lib/netselector.h"
#include "execute.h"
#include "configuration.tab.h"

static void set_env(const struct rule_set *rules, unsigned count) {
	unsigned i, j;
	char str[20], val[30];
	uint8_t *data;

	for(i = 0; i < count; i++) {
		if(!rules[i].matched) {
			continue;
		}
		for(j = 0; j < rules[i].count; j++) {
			str[0] = '\0';
			switch(rules[i].type) {
			case EAP:
				strcat(str,"EAP");
				break;
			case GATEWAY:
				strcat(str, "GATEWAY");
				break;
			case STP:
				strcat(str, "STP");
				break;
			case WIFI:
				strcat(str, "WIFI");
				break;
			case DHCPS:
				strcat(str, "DHCPS");
				break;
			case NBNS:
				strcat(str, "NBNS");
				break;
			case DNS:
				strcat(str, "DNS");
				break;
			case WLCCP:
				strcat(str, "WLCCP");
				break;
			case CDP:
				strcat(str, "CDP");
				break;
			default:
				printf("Unknown type\n");
				return;
				break;
			}
			switch(rules[i].items[j].type) {
			case MAC:
				strcat(str, "_MAC");
				data = rules[i].items[j].data;
				sprintf(val, "%02X:%02X:%02X:%02X:%02X:%02X", data[0], data[1],
					data[2], data[3], data[4], data[5]);
				setenv(str, val, 1);
				break;
			case ESSID:
				strcat(str, "_ESSID");
				setenv(str, rules[i].items[j].data, 1);
				break;
			case ROOT:
				strcat(str, "_ROOT");
				data = rules[i].items[j].data;
				sprintf(val, "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", data[0], data[1],
					data[2], data[3], data[4], data[5], data[6], data[7]);
				setenv(str, val, 1);
				break;
			case IP:
				strcat(str, "_IP");
				data = rules[i].items[j].data;
				sprintf(val, "%d.%d.%d.%d", IPQUAD(data));
				setenv(str, val, 1);
				break;
			case NAME:
				strcat(str, "_NAME");
				setenv(str, rules[i].items[j].data, 1);
				break;
			case ID:
				strcat(str, "_ID");
				setenv(str, rules[i].items[j].data, 1);
				break;
			default:
				printf("Unknown type\n");
				return;
				break;
			}
		}
	}
}

static void exec_async(const char *what) {
	pid_t pid;

	switch(pid = fork()) {
	case -1:
		printf("FORK FAILED\n");
		break;
	case 0:
		if(execlp(what, what, NULL) == -1) {
			exit(1);
		}
		exit(100); //Never should get here
		break;
	default:
		//parent continuing
		break;
	}
}

void exec_wait(void *arg) {
	int status;
	pid_t pid;
	pid = waitpid(-1, &status, WNOHANG);
	if(pid < 1) {
		return;
	}
	if(WIFEXITED(status) && !WEXITSTATUS(status)) { //Terminated with 0
		printf("Terminated normaly\n");
	} else {
		printf("Terminated abnormaly\n");
	}
}

int execute(struct network *net, unsigned action) {
	struct action_plan *plan;
	struct action *act;
	unsigned i;

	switch(action) {
	case EXEC_MATCH:
		act = net->match;
		setenv("ACTION", "UP", 1);
		break;
	case EXEC_DOWN:
		act = net->down;
		setenv("ACTION", "DOWN", 1);
	default:
		return 2;
		break;
	}
	if(!act) {
		return 3;
	}
	clearenv();//FIXME consider this line
	setenv("NETWORK", net->name, 1);
	setenv("PLAN", act->name, 1);
	set_env(net->rules, net->count);
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

