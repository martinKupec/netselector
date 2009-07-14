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

static void netlink_up(struct netlink_args *arg, const int intf) {
	printf("Interface %s carrier detected\n", arg->intf[intf].ifname);
	arg->intf[intf].link_up = 1;
}

static void netlink_down(struct netlink_args *arg, const int intf) {
	printf("Interface %s no-carrier\n", arg->intf[intf].ifname);
	arg->intf[intf].link_up = 0;
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
	//struct rtattr *data;
	//char intf[IFNAME_SIZE];

	len = recvmsg(arg->fd, &msg, 0);

	if(((ssize_t) (len)) < 0) {
		perror("Error from recvmgs: ");
		return 0;
	}

	for (nh = (struct nlmsghdr *) buf; NLMSG_OK (nh, len); nh = NLMSG_NEXT (nh, len)) {
		if(nh->nlmsg_type == NLMSG_DONE) {
			break;
		}
		/*switch(nh->nlmsg_type) {
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
		}*/
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
		/*printf("Index %d type %d flags %d change %d\n", info->ifi_index,
			info->ifi_type, info->ifi_flags, info->ifi_change);
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
		}*/
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
	if(register_module(&module_netlink)) {
		fprintf(stderr, "Unable to register netlink module\n");
		return 1;
	}
	return 0;
}

