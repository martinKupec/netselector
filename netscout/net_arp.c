#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include "netscout.h"
#include "network.h"
#include "link.h"
#include "list.h"

void net_arp_ether(const uint8_t *pkt, shell *sh) {
	const struct ether_arp *arp = (const struct ether_arp *) pkt;
	struct stat_ip *node = list_ip_add_uniq(arp->arp_spa);
	void *lower_node = sh->from.lower_node;

	node->ether = sh->from.lower_node;

	sh->from.lower_node = node;
	sh->from.higher_type = IP_TYPE_NONE;
	sh->from.higher_data = NULL;

	ip_node_set_info(&sh->from, sh->time);

	sh->from.lower_node = lower_node;
	sh->from.higher_type = ETH_TYPE_ARP;
	sh->from.higher_data = node;
	sh->to.higher_type = ETH_TYPE_NONE;
	sh->to.higher_data = NULL;
}

/*
 * Basi ARP handler
 */
void net_hndl_arp(const uint8_t *pkt, shell *sh) {
	const struct arphdr *hdr = (const struct arphdr *) pkt;
	const unsigned short hw_prot = ntohs(hdr->ar_hrd);

	switch(hw_prot) {
	case ARPHRD_ETHER:
		net_arp_ether(pkt, sh);
		break;
	default:
		sh->from.higher_type = ETH_TYPE_ARP_UNKNOWN;
		sh->from.higher_data = (void *) ((uint32_t) hw_prot);
		sh->to.higher_type = ETH_TYPE_NONE;
		sh->to.higher_data = NULL;
		break;
	}
}

