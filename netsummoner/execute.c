#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "netsummoner.h"
#include "lib/netselector.h"
#include "execute.h"
#include "wpa.h"
#include "netlink.h"
#include "configuration.tab.h"

struct exec_args {
	struct action *plan;
	struct network *net;
	struct combination *comb;
	unsigned action;
	unsigned actual;
	bool reversed;
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
	struct action_plan *plan = arg->plan->actions;
	char **prog;
	int ret;

	if(arg->reversed) {
		plan += arg->plan->count - arg->actual - 1;
	} else {
		plan += arg->actual;
	}

	if(arg->actual >= arg->plan->count) {
		printf("Execute done\n");
		if(arg->action == EXEC_MATCH) {
			arg->comb->active = true;
		} else {
			arg->comb->active = false;
		}
		arg->plan = NULL;
		return 11;
	}

	switch(plan->type) {
	case EXECUTE:
		prog = plan->data;


		clearenv();//FIXME consider this line
		setenv("NETWORK", arg->net->name, 1);
		setenv("PLAN", exec_arg.plan->name, 1);
		set_env(arg->net->rules, arg->net->count);
		if(arg->action == EXEC_MATCH) {
			setenv("ACTION", "UP", 1);
		} else {
			setenv("ACTION", "DOWN", 1);
		}

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
		printf("DHCP\n");
		return 1;
		break;
	case WPA:
		if(arg->action == EXEC_MATCH) {
			module_exec.fd = wpa_init(((const char **)(plan->data))[0]);
			if(module_exec.fd < 0) {
				fprintf(stderr, "WPA init error\n");
				return 1;
			}
			if((ret = wpa_connect(((const char **)(plan->data))[1], arg->net))) {
				printf("WPA Connect returned %d\n", ret);
				return 1;
			}
		} else {
			module_exec.fd = wpa_disconnect();
			if(module_exec.fd == -1) {
				arg->actual++;
				return exec_work(arg);
			}
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
	struct action_plan *plan = arg->plan->actions;
	int status;
	pid_t pid;

	if(arg->reversed) {
		plan += arg->plan->count - arg->actual - 1;
	} else {
		plan += arg->actual;
	}

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
		if(((arg->action == EXEC_MATCH) && (status == 0)) ||
				((arg->action == EXEC_DOWN) && (status == 4))) {
			arg->actual++;
		} else {
			return 0;
		}
		break;
	}
	return exec_work(arg);
}

static struct combination *choose_combination(struct assembly *ass) {
	size_t i;
	struct combination *cmbret = NULL;

	for(i = 0; i < ass->count; i++) {
		switch(ass->comb[i].condition) {
		case LINK:
			if(netlink_is_up(ass->comb[i].condition_args) == 1) {
				cmbret = ass->comb + i;
			}
			break;
		case FALLBACK:
			if(!cmbret) {
				cmbret = ass->comb + i;
			}
			break;
		}
	}
	return cmbret;
}

static struct combination *select_active_combination(struct assembly *ass) {
	size_t i;

	for(i = 0; i < ass->count; i++) {
		if(ass->comb[i].active) {
			return ass->comb + i;
		}
	}
	return NULL;
}

int execute_running(void) {
	return !!exec_arg.plan;
}

int execute(struct network *net, unsigned action) {
	struct assembly *anode;
	struct combination *comb;

	if(exec_arg.plan) {
		return 4;
	}

	LIST_WALK(anode, &list_assembly) {
		if(anode->net == net) {
			break;
		}
	}
	if(LIST_END(anode, &list_assembly))  {
		fprintf(stderr, "Execute: Unable to find assembly for network: %s\n", net->name);
		return 3;
	}

	printf("Executing assembly %s %s\n", anode->name, action == EXEC_MATCH ? "UP" : "DOWN");

	switch(action) {
	case EXEC_MATCH:
		comb = choose_combination(anode);
		printf("Combination %s\n", comb->condition == LINK ? "ethernet up" : "fallback");
		exec_arg.plan = comb->up;
		exec_arg.reversed = false;
		break;
	case EXEC_DOWN:
		comb = select_active_combination(anode);
		exec_arg.plan = comb->down;
		exec_arg.reversed = comb->down_reversed;
		break;
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
	exec_arg.comb = comb;

	module_exec.fnc = (dispatch_callback) exec_wait;
	module_exec.arg = &exec_arg;
	module_exec.timeout = -1;
	if(register_module(&module_exec, "Exec")) {
		return 3;
	}
	return exec_work(&exec_arg);
}

