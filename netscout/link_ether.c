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
}
