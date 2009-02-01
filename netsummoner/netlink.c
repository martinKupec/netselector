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


int netlink_init(void) {
	int fd;
	size_t len;
	char buf[4096];
	struct sockaddr_nl sa;
	struct iovec iov = { buf, sizeof(buf) };
	struct nlmsghdr *nh;
	struct msghdr msg = { (void *)&sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	struct ifinfomsg *info;
	struct rtattr *data;

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

	bzero(&sa, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK;
	sa.nl_pid = getpid();
	bind(fd, (struct sockaddr *) &sa, sizeof(sa));

	for(;;) {
	len = recvmsg(fd, &msg, 0);

	for (nh = (struct nlmsghdr *) buf; NLMSG_OK (nh, len); nh = NLMSG_NEXT (nh, len)) {
		if(nh->nlmsg_type == NLMSG_DONE) {
			break;
		}
		switch(nh->nlmsg_type) {
		case NLMSG_ERROR:
			printf("ERROR\n");
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
		}
		info = NLMSG_DATA(nh);
		printf("Index %d type %d up %d flags %d change %d\n", info->ifi_index,
			info->ifi_type, info->ifi_flags & IFF_UP, info->ifi_flags, info->ifi_change);
		data = (struct rtattr*) ((char*) info + NLMSG_ALIGN(sizeof(struct ifinfomsg)));
		len = NLMSG_PAYLOAD(nh, sizeof(struct ifinfomsg));
		
		while(RTA_OK(data, len)) {
			switch(data->rta_type) {
			case IFLA_IFNAME:
				{
				char *name[100];
				int l = RTA_PAYLOAD(data);

				strncpy(name, RTA_DATA(data), l);

				printf("Inf name %s\n", name);
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
				struct net_device_stats *st = RTA_DATA(data);
				printf("Inf stat\n");
				break;
				}
			}
			data = RTA_NEXT(data, len);
		}
	}

	}

	return 0;
}
