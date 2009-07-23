#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/types.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/if.h>

#include "netlink.h"
#include "execute.h"
#include "netsummoner.h"
#include "configuration.tab.h"

#define IFNAME_SIZE 10
#define INTF_NO 3

struct intf_data {
	char ifname[IFNAME_SIZE];
	int if_index;
	int link_up;
};

struct netlink_args {
	int fd;
	struct sockaddr_nl sa;
	struct intf_data intf[INTF_NO];
};

struct netlink_args netlink_arg;
struct module_info module_netlink;

static void netlink_change(bool up) {
	unsigned i;
	struct assembly *anode;

	LIST_WALK(anode, &list_assembly) {
		for(i = 0; i < anode->count; i++) {
			if(anode->comb[i].active) {
				if(!up && anode->comb[i].condition == LINK) {
					if(!netlink_is_up(anode->comb[i].condition_args)) {
						execute(anode->net, EXEC_RESTART);
					}
				} else if(up && anode->comb[i].condition != LINK) {
					for(i = 0; i < anode->count; i++) {
						if(anode->comb[i].condition == LINK) {
							if(netlink_is_up(anode->comb[i].condition_args)) {
								execute(anode->net, EXEC_RESTART);
							}
							break;
						}
					}
				}
				break;
			}
		}
	}
}

static void netlink_up(struct netlink_args *arg, const int intf) {
	if(!arg->intf[intf].link_up) {
		printf("Interface %s carrier detected\n", arg->intf[intf].ifname);
		arg->intf[intf].link_up = 1;
		netlink_change(1);
	}
}

static void netlink_down(struct netlink_args *arg, const int intf) {
	if(arg->intf[intf].link_up) {
		printf("Interface %s no-carrier\n", arg->intf[intf].ifname);
		arg->intf[intf].link_up = 0;
		netlink_change(0);
	}
}

int netlink_is_up(const char *intf) {
	int i;

	for(i = 0; i < INTF_NO; i++) {
		if(!strcmp(netlink_arg.intf[i].ifname, intf)) {
			return netlink_arg.intf[i].link_up;
		}
	}
	return 3;
}

static int netlink_send_msg(const struct netlink_args *arg, const int intf, const int type, const int flags) {
	uint8_t req[1024];
	struct nlmsghdr *nh = (struct nlmsghdr *) req;
	struct ifinfomsg *info;
	struct iovec iov = { (void *) nh, nh->nlmsg_len }; //Length need's to change later
	struct sockaddr_nl sa;
	struct msghdr msg = { (void *)&sa, sizeof(struct sockaddr_nl), &iov, 1, NULL, 0, 0 };

	bzero(&sa, sizeof(struct sockaddr_nl));
	sa.nl_family = AF_NETLINK; //Others zero

	bzero(&req, sizeof(req)); 
	nh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nh->nlmsg_type = type;
	nh->nlmsg_flags = NLM_F_REQUEST;
	nh->nlmsg_pid = 0; // Kernel
	nh->nlmsg_seq = 1; //This is first and last message we send

	info = NLMSG_DATA(nh);
	info->ifi_family = AF_UNSPEC;
	info->ifi_index = arg->intf[intf].if_index;
	info->ifi_type = 0;
	info->ifi_flags = flags;
	info->ifi_change = 0xFFFFFFFF;

	iov.iov_len = nh->nlmsg_len;
	if(sendmsg(arg->fd, &msg, 0) == -1) {
		perror("Netlink send error: ");
		return -1;
	}
	return 0;
}

static int netlink_send_request(const struct netlink_args *arg, const int intf) {
	return netlink_send_msg(arg, intf, RTM_GETLINK, 0);
}

static int netlink_up_intf(const struct netlink_args *arg, const int intf) {
	return netlink_send_msg(arg, intf, RTM_NEWLINK, IFF_UP);
}

static int netlink_callback(struct netlink_args *arg) {
	int i;
	char buf[4096];
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg = { (void *)&arg->sa, sizeof(struct sockaddr_nl), &iov, 1, NULL, 0, 0 };
	size_t len;
	struct nlmsghdr *nh;
	struct ifinfomsg *info;

	len = recvmsg(arg->fd, &msg, 0);

	if(((ssize_t) (len)) < 0) {
		perror("Error from recvmgs: ");
		return 0;
	}

	for (nh = (struct nlmsghdr *) buf; NLMSG_OK (nh, len); nh = NLMSG_NEXT (nh, len)) {
		if(nh->nlmsg_type == NLMSG_DONE) {
			break;
		}
		info = NLMSG_DATA(nh);
		for(i = 0; i < INTF_NO; i++) {
			if(arg->intf[i].if_index == info->ifi_index) {
				if(info->ifi_flags & IFF_LOWER_UP) {
					netlink_up(arg, i);
				} else {
					netlink_down(arg, i);
				}
			}
		}
	}
	return 0;
}

int netlink_init(const char **intf) {
	int fd;
	int i;

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if(fd < 0) {
		return 1;
	}

	bzero(&netlink_arg.sa, sizeof(struct sockaddr_nl));
	netlink_arg.sa.nl_family = AF_NETLINK;
	netlink_arg.sa.nl_groups = RTMGRP_LINK;
	netlink_arg.sa.nl_pid = getpid();
	if(bind(fd, (struct sockaddr *) &netlink_arg.sa, sizeof(struct sockaddr_nl))) {
		perror("Netlink bind: ");
		return 1;
	}

	for(i = 0; i < INTF_NO; i++) {
		if(intf[i] == NULL) {
			break;
		}
		strcpy(netlink_arg.intf[i].ifname, intf[i]);
		netlink_arg.intf[i].link_up = 0;
		netlink_arg.intf[i].if_index = if_nametoindex(intf[i]);
	}
	for(; i < INTF_NO; i++) {
		netlink_arg.intf[i].ifname[0] = '\0';
		netlink_arg.intf[i].link_up = 0;
		netlink_arg.intf[i].if_index = -1;
	}

	netlink_arg.fd = fd;

	module_netlink.fnc = (dispatch_callback) netlink_callback;
	module_netlink.arg = &netlink_arg;
	module_netlink.fd = fd; 
	module_netlink.timeout = -2;

	for(i = 0; i < INTF_NO; i++) {
		if(netlink_arg.intf[i].ifname[0] == '\0') {
			continue;
		}
		printf("Bringing interface %s up\n", netlink_arg.intf[i].ifname);
		if(netlink_up_intf(&netlink_arg, i)) {
			fprintf(stderr, "Failed to bring %s up\n", netlink_arg.intf[i].ifname);
			return 2;
		}
		if(netlink_send_request(&netlink_arg, i)) {
			fprintf(stderr, "Unable to send netlink request\n");
			return 3;
		}
	}
	if(register_module(&module_netlink, "Netlink")) {
		fprintf(stderr, "Unable to register netlink module\n");
		return 1;
	}
	return 0;
}

void netlink_deinit(void) {
	close(netlink_arg.fd);
	module_netlink.timeout = -3; //Unregister
}
