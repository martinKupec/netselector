#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "netsummoner.h"
#include "lib/netselector.h"
#include "execute.h"
#include "wpa.h"
#include "configuration.tab.h"

struct exec_args {
	struct action *plan;
	struct network *net;
	unsigned action;
	unsigned actual;
	pid_t pid;
};

struct exec_args exec_arg;
struct module_info module_exec;

static void signal_child(int sig UNUSED) {
	printf("Child died\n");
}

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

static int exec_work(struct exec_args *arg) {
	struct action_plan *plan = arg->plan->actions + arg->actual;
	char **prog;
	int ret;

	if(arg->actual >= arg->plan->count) {
		printf("Execute done\n");
		return 11;
	}

	switch(plan->type) {
	case EXECUTE:
		printf("Execute\n");
		prog = plan->data;


		clearenv();//FIXME consider this line
		setenv("NETWORK", arg->net->name, 1);
		setenv("PLAN", exec_arg.plan->name, 1);
		set_env(arg->net->rules, arg->net->count);

		signal(SIGCHLD, signal_child);

		module_exec.fd = -1;

		switch(arg->pid = fork()) {
		case -1:
			printf("FORK FAILED\n");
			return 3;
			break;
		case 0:
			if(execvp(prog[0], prog) == -1) {
				exit(1);
			}
			exit(100); //Never should get here
			break;
		default:
			//parent continuing
			break;
		}
		break;
	case DHCP:
		printf("Dhcp\n");
		return 1;
		break;
	case WPA:
		printf("WPA\n");

		module_exec.fd = wpa_init(((const char **)(plan->data))[0]);
		if(module_exec.fd < 0) {
			fprintf(stderr, "WPA init error\n");
			return 1;
		}
		if(arg->action == EXEC_MATCH) {
			if((ret = wpa_connect(((const char **)(plan->data))[1]))) {
				printf("WPA Connect returned %d\n", ret);
				return 1;
			}
		} else {
			wpa_disconnect();
		}
		break;
	default:
		fprintf(stderr, "Unknown action type %d\n", plan->type);
		return 2;
		break;
	}
	return 0;
}

static int exec_wait(struct exec_args *arg) {
	struct action_plan *plan = arg->plan->actions + arg->actual;
	int status;
	pid_t pid;

	switch(plan->type) {
	case EXECUTE:
		pid = waitpid(-1, &status, WNOHANG);
		if(pid < 1) {
			return 0;
		}
		if(pid != arg->pid) {
			printf("Exited different child\n");
			return 0;
		}

		if(!WIFEXITED(status)) {
			printf("Died but not exited...killed\n");
			return 1;
		} else {
			if(WEXITSTATUS(status)) { //Terminated with non zero
				printf("Terminated abnormaly, return code %d\n", WEXITSTATUS(status));
				return 1;//rollback ??
			}
		}
		arg->actual++;
		break;
	case DHCP:
		return 2;
		break;
	case WPA:
		status = wpa_message();
		if(!status) {
			arg->actual++;
		} else {
			return 0;
		}
		break;
	}
	return exec_work(arg);
}

int execute(struct network *net, unsigned action) {

	switch(action) {
	case EXEC_MATCH:
		exec_arg.plan = net->match;
		setenv("ACTION", "UP", 1);
		break;
	case EXEC_DOWN:
		exec_arg.plan = net->down;
		setenv("ACTION", "DOWN", 1);
	default:
		return 1;
		break;
	}
	if(!exec_arg.plan) {
		return 2;
	}
	exec_arg.actual = 0;
	exec_arg.action = action;
	exec_arg.net = net;

	module_exec.fnc = (dispatch_callback) exec_wait;
	module_exec.arg = &exec_arg;
	module_exec.timeout = -1;
	if(register_module(&module_exec)) {
		return 3;
	}
	return exec_work(&exec_arg);
}

