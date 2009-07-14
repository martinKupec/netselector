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
	raise(SIGUSR1);
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

static int call_module(const size_t i) {
	int ret;
	struct module_register *module = mod_reg + i;

	ret = module->mod->fnc(module->mod->arg);
	module = mod_reg + i; //needed because of reallocing of mod_reg

	if(ret) {
		unregister_module(module->mod);
		return 1;
	} else {
		module->timeout_left = module->mod->timeout;
		return 0;
	}
}

int dispatch_loop(void) {
	struct timeval time_start, time_end;
	struct timespec timeout;
	sigset_t sigmask, sigorig;
	int retval;
	size_t i;
	int fd_max, wait_min;
	fd_set fd_read;

	signal(SIGINT, signal_hndl);
	signal(SIGUSR1, SIG_IGN);

	gettimeofday(&time_start, NULL);
	start_time = time_start.tv_sec * 1000 + (time_start.tv_usec / 1000);

	sigfillset(&sigmask);
	sigdelset(&sigmask, SIGINT);
	sigprocmask(SIG_SETMASK, &sigmask, &sigorig);
	sigemptyset(&sigmask);

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
		timeout.tv_nsec = wait_min * 1000L * 1000;
		gettimeofday(&time_start, NULL); //FIXME global flag and pselect
		retval = pselect(fd_max + 1, &fd_read, NULL, NULL, &timeout, &sigmask);
		gettimeofday(&time_end, NULL);
		wait_min = (time_end.tv_sec - time_start.tv_sec) * 1000;
		if(time_end.tv_usec < time_start.tv_usec) {
			wait_min -= (time_start.tv_usec - time_end.tv_usec) / 1000;
		} else {
			wait_min += (time_end.tv_usec - time_start.tv_usec) / 1000;
		}
		if(retval < 0) { //probably interrupted by signal
			if(errno == EINTR) { //interrupted by signal
				if(signal_stop) { //interrupted by user
					break;
				}
				//timeout -1 specifies wait for signal
				for(i = 0; i < mod_reg_size; i++) {
					if(mod_reg[i].mod->timeout == -1) {
						i -= call_module(i);
					}
				}
			} else {
				perror("Select failed:");
			}
		} else {
			for(i = 0; i < mod_reg_size; i++) {
				if(mod_reg[i].mod->fd > 0) { //Valid fd ?
					if(FD_ISSET(mod_reg[i].mod->fd, &fd_read)) {
						i -= call_module(i);
						continue;
					}
				}
				if(mod_reg[i].timeout_left > 0) { //Valid timeout ?
					if(mod_reg[i].timeout_left <= wait_min) { // timed out
						i -= call_module(i);
						continue;
					} else {
						mod_reg[i].timeout_left -= wait_min;
					}
				}
			}
		}
	}
	sigprocmask(SIG_SETMASK, &sigorig, NULL);
	signal(SIGINT, SIG_DFL);
	return 0;
}
