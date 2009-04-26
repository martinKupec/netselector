#ifndef __NETSUMMONER_NETLINK_H__
#define __NETSUMMONER_NETLINK_H__

int netlink_init(const char *intf);
int netlink_is_up(const char *intf);

#endif
