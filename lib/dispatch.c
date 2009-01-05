#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/select.h>

#include "lib/netselector.h"

struct module_register {
	struct module_info *mod;
	int timeout_left;
};

static volatile bool signal_stop;
static struct module_register *mod_reg;
static size_t mod_reg_size;
uint64_t start_time;

/*
 * Signal handler for terminating
 */
static void signal_hndl(int sig UNUSED) {
	signal_stop = 1;
	signal(SIGINT, SIG_DFL);
}

void dispatch_stop(void) {
	signal_stop = 1;
}

int register_module(struct module_info *reg) {
	struct module_register *tmp;

	mod_reg_size++;
	tmp = realloc(mod_reg, sizeof(struct module_register) * mod_reg_size);
	if(!tmp) {
		mod_reg_size--;
		return 1;
	}
	mod_reg = tmp;
	mod_reg[mod_reg_size - 1].mod = reg;
	mod_reg[mod_reg_size - 1].timeout_left = reg->timeout;
	return 0;
}

static void unregister_module(const struct module_info *reg) {
	size_t i;

	for(i = 0; i < mod_reg_size; i++) {
		if(mod_reg[i].mod == reg) {
			fprintf(stderr, "Unregistering module\n");
			memcpy(mod_reg + i, mod_reg + mod_reg_size - 1, sizeof(struct module_register));
			mod_reg_size--;
			if(!mod_reg_size) {
				free(mod_reg);
				mod_reg = NULL;
			} else {
				mod_reg = realloc(mod_reg, sizeof(struct module_register) * mod_reg_size);
			}
			break;
		}
	}
}

static int call_module(struct module_register *module) {
	if(module->mod->fnc(module->mod->arg)) {
		unregister_module(module->mod);
		return 1;
	} else {
		module->timeout_left = module->mod->timeout;
		return 0;
	}
}

int dispatch_loop(void) {
	struct timeval timeout, time;
	int retval;
	size_t i;
	int fd_max, wait_min;
	fd_set fd_read;

	signal(SIGINT, signal_hndl);

	gettimeofday(&time, NULL);
	start_time = time.tv_sec * 1000 + (time.tv_usec / 1000);

	while(!signal_stop) {
		FD_ZERO(&fd_read);
		fd_max = -1;
		wait_min = 5000; //5s is sufficently long
		for(i = 0; i < mod_reg_size; i++) {
			if(mod_reg[i].mod->fd > 0) { //Valid fd ?
				FD_SET(mod_reg[i].mod->fd, &fd_read);
				if(mod_reg[i].mod->fd > fd_max) {
					fd_max = mod_reg[i].mod->fd;
				}
			}
			if(mod_reg[i].timeout_left > 0) { //Valid timeout ?
				if(mod_reg[i].timeout_left < wait_min) {
					wait_min = mod_reg[i].timeout_left;
				}
			}
		}
		timeout.tv_sec = 0;
		timeout.tv_usec = wait_min * 1000;
		gettimeofday(&time, NULL); //FIXME global flag and pselect
		retval = select(fd_max + 1, &fd_read, NULL, NULL, &timeout);
		gettimeofday(&timeout, NULL);
		wait_min = (timeout.tv_sec - time.tv_sec) * 1000;
		if(timeout.tv_usec < time.tv_usec) {
			wait_min -= (time.tv_usec - timeout.tv_usec) / 1000;
		} else {
			wait_min += (timeout.tv_usec - time.tv_usec) / 1000;
		}
		if(retval < 0) { //probably interrupted by signal
			if(errno == EINTR) { //interrupted by signal
				//timeout -1 specifies wait for signal
				for(i = 0; i < mod_reg_size; i++) {
					if(mod_reg[i].mod->timeout == -1) {
						i -= call_module(mod_reg + i);
					}
				}
			} else {
				perror("Select failed:");
			}
		} else {
			for(i = 0; i < mod_reg_size; i++) {
				if(mod_reg[i].mod->fd > 0) { //Valid fd ?
					if(FD_ISSET(mod_reg[i].mod->fd, &fd_read)) {
						i -= call_module(mod_reg + i);
					}
				} else if(mod_reg[i].timeout_left > 0) { //Valid timeout ?
					if(mod_reg[i].timeout_left <= wait_min) { // timed out
						i -= call_module(mod_reg + i);
					} else {
						mod_reg[i].timeout_left -= wait_min;
					}
				}
			}
		}
	}
	signal(SIGINT, SIG_DFL);
	return 0;
}
