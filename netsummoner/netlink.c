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
#include "netsummoner.h"

#define IFNAME_SIZE 10

struct netlink_args {
	int fd;
	struct sockaddr_nl sa;
	char ifname[IFNAME_SIZE];
};

struct netlink_args netlink_arg;
struct module_info module_netlink;

static void netlink_up(struct netlink_args *arg) {
	printf("NETLINK UP\n");
}

static void netlink_down(struct netlink_args *arg) {
	printf("NETLINK DOWN\n");
}

static int netlink_callback(struct netlink_args *arg) {
	char buf[4096];
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg = { (void *)&arg->sa, sizeof(struct sockaddr_nl), &iov, 1, NULL, 0, 0 };
	size_t len;
	struct nlmsghdr *nh;
	struct ifinfomsg *info;
	struct rtattr *data;
	char intf[IFNAME_SIZE];

	len = recvmsg(arg->fd, &msg, 0);

	if(((ssize_t) (len)) < 0) {
		printf("Error from recvmgs\n");
		return 0;
	}

	for (nh = (struct nlmsghdr *) buf; NLMSG_OK (nh, len); nh = NLMSG_NEXT (nh, len)) {
		if(nh->nlmsg_type == NLMSG_DONE) {
			break;
		}
		switch(nh->nlmsg_type) {
		case NLMSG_ERROR:
			printf("ERROR\n");
			return 0;
			break;
		case RTM_NEWLINK:
			printf("NT NEW\n");
			break;
		case RTM_DELLINK:
			printf("NT DEL\n");
			break;
		case RTM_GETLINK:
			printf("NT GET\n");
			break;
		}
		if(!NLMSG_OK(nh, len)) {
			printf("message not OK\n");
			return 0;
		}
		info = NLMSG_DATA(nh);
		printf("Index %d type %d up %d flags %d change %d\n", info->ifi_index,
			info->ifi_type, info->ifi_flags & IFF_UP, info->ifi_flags, info->ifi_change);
		printf("Inf flags:\n\
IFF_UP %d\n\
IFF_BROADCAST %d\n\
IFF_DEBUG %d\n\
IFF_LOOPBACK %d\n\
IFF_POINTOPOINT %d\n\
IFF_NOTRAILERS %d\n\
IFF_RUNNING %d\n\
IFF_NOARP %d\n\
IFF_PROMISC %d\n\
IFF_ALLMULTI %d\n\
IFF_MASTER %d\n\
IFF_SLAVE %d\n\
IFF_MULTICAST %d\n\
IFF_PORTSEL %d\n\
IFF_AUTOMEDIA %d\n\
IFF_DYNAMIC %d\n\
IFF_LOWER_UP %d\n\
IFF_DORMANT %d\n\
IFF_ECHO %d\n"
		,info->ifi_flags & IFF_UP
		,info->ifi_flags & IFF_BROADCAST
		,info->ifi_flags & IFF_DEBUG
		,info->ifi_flags & IFF_LOOPBACK
		,info->ifi_flags & IFF_POINTOPOINT
		,info->ifi_flags & IFF_NOTRAILERS
		,info->ifi_flags & IFF_RUNNING
		,info->ifi_flags & IFF_NOARP
		,info->ifi_flags & IFF_PROMISC
		,info->ifi_flags & IFF_ALLMULTI
		,info->ifi_flags & IFF_MASTER
		,info->ifi_flags & IFF_SLAVE
		,info->ifi_flags & IFF_MULTICAST
		,info->ifi_flags & IFF_PORTSEL
		,info->ifi_flags & IFF_AUTOMEDIA
		,info->ifi_flags & IFF_DYNAMIC
		,info->ifi_flags & IFF_LOWER_UP
		,info->ifi_flags & IFF_DORMANT
		,info->ifi_flags & IFF_ECHO);


		data = (struct rtattr*) ((char*) info + NLMSG_ALIGN(sizeof(struct ifinfomsg)));
		len = NLMSG_PAYLOAD(nh, sizeof(struct ifinfomsg));
		
		intf[0] = '\0';
		while(RTA_OK(data, len)) {
			switch(data->rta_type) {
			case IFLA_IFNAME:
				{
				int l = RTA_PAYLOAD(data);

				strncpy(intf, RTA_DATA(data), l);

				printf("Inf name %s\n", intf);
				}
				break;
			case IFLA_ADDRESS:
				printf("Inf address\n");
				break;
			case IFLA_BROADCAST:
				printf("Inf broadcast\n");
				break;
			case IFLA_LINK:
				printf("Inf link %d\n", *((unsigned int*)RTA_DATA(data)));
				break;
			case IFLA_QDISC:
				printf("Inf qdisc\n");
				break;
			case IFLA_STATS:
				{
				//struct net_device_stats *st = RTA_DATA(data);
				printf("Inf stat\n");
				break;
				}
			}
			data = RTA_NEXT(data, len);
		}
		if(!strcmp(arg->ifname, intf)) {
			if(info->ifi_flags & IFF_RUNNING) {
				netlink_up(arg);
			} else {
				netlink_down(arg);
			}
		}
	}
	return 0;
}

int netlink_init(const char *intf) {
	int fd;

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if(fd < 0) {
		return -1;
	}

	bzero(&netlink_arg.sa, sizeof(struct sockaddr_nl));
	netlink_arg.sa.nl_family = AF_NETLINK;
	netlink_arg.sa.nl_groups = RTMGRP_LINK;
	netlink_arg.sa.nl_pid = getpid();
	bind(fd, (struct sockaddr *) &netlink_arg.sa, sizeof(struct sockaddr_nl));

	strcpy(netlink_arg.ifname, intf);

	module_netlink.fnc = (dispatch_callback) netlink_callback;
	module_netlink.arg = &netlink_arg;
	module_netlink.fd = fd; 
	module_netlink.timeout = -2;
	return fd;
}

