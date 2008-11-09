#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include "netselector.h"
#include "network.h"
#include "link.h"
#include "list.h"
#include "score.h"
#include "node_info.h"

/*
 * Handles ARP packets on ethernet
 */
static unsigned net_arp_ether(const uint8_t *pkt, shell *sh) {
	const struct ether_arp *arp = (const struct ether_arp *) pkt;
	struct stat_ip *node = get_node_ip(*((uint32_t *) arp->arp_spa));
	void *lower_node = sh->from.lower_node;
	unsigned score = 0;

	if(!node->count) {
		score += SCORE_IP;
	}

	node->ether = sh->from.lower_node;

	sh->from.lower_node = node;
	sh->from.higher_type = IP_TYPE_ARP;
	sh->from.higher_data = NULL;

	score += ip_node_set_info(&sh->from, sh->time);

	sh->from.lower_node = lower_node;
	sh->from.higher_type = ETH_TYPE_IP;
	sh->from.higher_data = node;
	sh->to.higher_type = ETH_TYPE_NONE;
	sh->to.higher_data = NULL;
	return score;
}

/*
 * Basi ARP handler
 */
unsigned net_hndl_arp(const uint8_t *pkt, shell *sh) {
	const struct arphdr *hdr = (const struct arphdr *) pkt;
	const unsigned short hw_prot = ntohs(hdr->ar_hrd);
	unsigned score = 0;

	switch(hw_prot) {
	case ARPHRD_ETHER:
		score += net_arp_ether(pkt, sh);
		break;
	default:
		sh->from.higher_type = ETH_TYPE_ARP_UNKNOWN;
		sh->from.higher_data = (void *) ((uint32_t) hw_prot);
		sh->to.higher_type = ETH_TYPE_NONE;
		sh->to.higher_data = NULL;
		break;
	}
	return score;
}

