#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/llc.h>

#include "netscout.h"
#include "network.h"
#include "link.h"
#include "list.h"

struct llc_header {
	uint8_t dsap;
	uint8_t ssap;
	uint8_t control;
} PACKED;

/*
 * Makes room for info and places it in right place
 */
static void ether_node_set_info(const struct shell_exchange *ex, const uint32_t time) {
	struct stat_ether *node = ex->lower_node;
	struct info_field my = {.type = ex->higher_type, .time = time};
	unsigned here;

	if(node->info == NULL) {
		node->info = (struct info_field *) malloc(sizeof(struct info_field) * 16); 
	} else {
		if((node->count & 0x0F) == 0x0F) { // mod 16 is 0
			node->info = (struct info_field *) realloc(node->info, sizeof(struct info_field) * (node->count + 16));
		}
	}
	if(!node->count) { //Nothing here yet
		here = 0;
	} else if(memcmp(&my, node->info + node->count - 1, sizeof(uint32_t) * 2) > 0) { //Last is before
		here = node->count;
	} else { //Need to put inside
		for(here = 0; here < node->count; here++) {
			if(memcmp(&my, node->info + node->count - 1, sizeof(uint32_t) * 2) > 0) {
				break;
			}
			bcopy(node->info + here, node->info + here + 1, sizeof(struct info_field) * (node->count - here));
		}
	}
	node->info[here].type = ex->higher_type;
	node->info[here].data = ex->higher_data;
	node->info[here].time = time;
}

/*
 * Basic handler for ethernet link layer
 */
void link_hndl_ether(const uint8_t *pkt, shell *sh) {
	const struct ether_header *hdr = (const struct ether_header *) pkt;
	const uint16_t etype = ntohs(hdr->ether_type);
	const uint8_t *ether_payload = pkt + sizeof(struct ether_header);
	
	sh->from.lower_node = list_ether_add_uniq(hdr->ether_shost);;
	sh->to.lower_node = list_ether_add_uniq(hdr->ether_dhost);

	switch(etype) {
	case ETHERTYPE_IP:
		net_hndl_ip(ether_payload, sh);
		break;
	case ETHERTYPE_ARP:
		net_hndl_arp(ether_payload, sh);
		break;
	case ETHERTYPE_REVARP:
		sh->from.higher_type = ETH_TYPE_REVARP;
		sh->from.higher_data = NULL;
		sh->to.higher_type = ETH_TYPE_NONE;
		sh->to.higher_data = NULL;
		break;
	case ETHERTYPE_VLAN:
		sh->from.higher_type = ETH_TYPE_VLAN;
		sh->from.higher_data = NULL;
		sh->to.higher_type = ETH_TYPE_NONE;
		sh->to.higher_data = NULL;
		break;
	case ETHERTYPE_EAP:
		net_hndl_eap(ether_payload, sh);
		break;
	default:
		if(etype <= 1500) {
			const struct llc_header *llc_hdr = (const struct llc_header *) ether_payload;

			ether_payload += 2 + ((llc_hdr->control & 0x03) == 3 ? 1 : 2);
			switch(llc_hdr->dsap) {
			case LLC_SAP_BSPAN:
				net_hndl_stp(ether_payload, sh);
				//FIXME - probably remove to
				break;
			case LLC_SAP_SNAP:
				net_hndl_snap((uint8_t *)llc_hdr, sh);
				break;
			default:
				sh->from.higher_type = ETH_TYPE_LLC_UNKNOWN;
				sh->from.higher_data = (void *) ((llc_hdr->dsap << 8) | llc_hdr->ssap); //Ugly but efficient
				sh->to.higher_type = ETH_TYPE_NONE;
				sh->to.higher_data = NULL;
				break;
			}
		} else {
			sh->from.higher_type = ETH_TYPE_UNKNOWN;
			sh->from.higher_data = (void *) ((uint32_t) etype); //Ugly but efficient
			sh->to.higher_type = ETH_TYPE_NONE;
			sh->to.higher_data = NULL;
		}
		break;
	}

	ether_node_set_info(&sh->to, sh->time);
	ether_node_set_info(&sh->from, sh->time);
	return;
}
