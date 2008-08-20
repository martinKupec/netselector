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
#include "list.h"

struct llc_header {
	uint8_t dsap;
	uint8_t ssap;
	uint8_t control;
};

static inline void use_possibly_new_node(struct stat_ether *node, uint8_t *addr, shell *sh) {
	if(node->time == NULL) {
		memcpy(node->addr, addr, ETHER_ADDR_LEN);
		node->time = (uint32_t *) malloc(sizeof(uint32_t) * 16); 
	} else {
		if((node->time_count & 0x0F) == 0x0F) {
			node->time = (uint32_t *) realloc(node->time, sizeof(uint32_t) * (node->time_count + 16));
		}
	}
	node->time[node->time_count++] = sh->time;
}

void link_hndl_ether(const uint8_t *pkt, shell *sh) {
	struct ether_header *hdr = (struct ether_header *) pkt;
	uint16_t etype = ntohs(hdr->ether_type);
	const uint8_t *ether_payload = pkt + sizeof(struct ether_header);
	const struct llc_header *llc_hdr = (const struct llc_header *) ether_payload;
	struct stat_ether *node = list_ether_add_uniq(hdr->ether_dhost);
	
	use_possibly_new_node(node, hdr->ether_dhost, sh);
	sh->lower_to = node;
	sh->lower_to_args = node->time + node->time_count - 1;

	node = list_ether_add_uniq(hdr->ether_shost);

	use_possibly_new_node(node, hdr->ether_shost, sh);
	sh->lower_from = node;
	sh->lower_from_args = node->time + node->time_count - 1;

	switch(etype) {
	case ETHERTYPE_IP:
		net_hndl_ip(ether_payload);
		break;
	case ETHERTYPE_ARP:
		net_hndl_arp(ether_payload);
		break;
	case ETHERTYPE_REVARP:
		printf("Type:RARP\n");
		break;
	case ETHERTYPE_VLAN:
		printf("Type:VLAN\n");
		break;
	default:
		if(etype <= 1500) {
			ether_payload += 2 + ((llc_hdr->control & 0x03) == 0x3 ? 1 : 2);
			switch(llc_hdr->dsap) {
			case LLC_SAP_BSPAN:
				net_hndl_stp(ether_payload);
				break;
			case LLC_SAP_SNAP:
				net_hndl_snap((uint8_t *)llc_hdr);
				break;
			default:
				printf("DSAP:%02X SSAP:%02X\n", llc_hdr->dsap, llc_hdr->ssap);
				break;
			}
		} else {
			printf("Type:%04X\n", etype);
		}
		break;
	}
	return;
}
