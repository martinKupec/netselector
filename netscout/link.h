#ifndef __NETSCOUT_LINK_H__
#define __NETSCOUT_LINK_H__

#include <stdint.h>

#define ETHERTYPE_EAP	0x888e

void link_hndl_ether(const uint8_t *pkt, shell *sh);

enum {
	ETH_TYPE_NONE,
	ETH_TYPE_IP,
	ETH_TYPE_ARP,
	ETH_TYPE_REVARP,
	ETH_TYPE_VLAN,
	ETH_TYPE_EAP,
	ETH_TYPE_ARP_UNKNOWN,
	ETH_TYPE_LLC_UNKNOWN,
	ETH_TYPE_UNKNOWN,
	ETH_TYPE_LAST
};

#endif

