#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include "netscout.h"
#include "network.h"
#include "list.h"

typedef unsigned char byte;
#define IPQUAD(x) ((byte*)&(x))[0], ((byte*)&(x))[1], ((byte*)&(x))[2], ((byte*)&(x))[3]

void net_arp_ether(const uint8_t *pkt, shell *sh) {
	const struct ether_arp *eap = (const struct ether_arp *) pkt;
	struct stat_ip *node = list_ip_add_uniq(eap->arp_spa);

	if(node->ether == NULL) {
		node->ether = (struct stat_ether **) malloc(sizeof(struct stat_ether *) * 16);
		node->time = (uint32_t *) malloc(sizeof(uint32_t) * 16);
	} else {
		if((node->ether_count & 0x0F) == 0x0F) {
			node->ether = (struct stat_ether **) realloc(node->ether, sizeof(struct stat_ether *) * (node->ether_count + 16));
			node->time = (uint32_t *) realloc(node->time, sizeof(uint32_t) * (node->ether_count + 16));
		}
	}
	node->ether[node->ether_count] = sh->lower_from;
	node->time[node->ether_count++] = sh->time;
	//FIXME maybe test it from and to Ether is the same - should be

	//printf("Prot F:%03d.%03d.%03d.%03d Prot T:%03d.%03d.%03d.%03d ",
	//printf("HW F:%02X:%02X:%02X:%02X:%02X:%02X HW T:%02X:%02X:%02X:%02X:%02X:%02X Prot F:%03d.%03d.%03d.%03d Prot T:%03d.%03d.%03d.%03d ",
		/*eap->arp_sha[0],
		eap->arp_sha[1],
		eap->arp_sha[2],
		eap->arp_sha[3],
		eap->arp_sha[4],
		eap->arp_sha[5],
		eap->arp_tha[0],
		eap->arp_tha[1],
		eap->arp_tha[2],
		eap->arp_tha[3],
		eap->arp_tha[4],
		eap->arp_tha[5],*/
		/*IPQUAD(eap->arp_spa),
		IPQUAD(eap->arp_tpa)
		);*/
	return;
}

void net_hndl_arp(const uint8_t *pkt, shell *sh) {
	const struct arphdr *hdr = (const struct arphdr *) pkt;
	unsigned short int hw_prot = ntohs(hdr->ar_hrd);

	switch(hw_prot) {
	case ARPHRD_ETHER:
		net_arp_ether(pkt, sh);
		break;
	default:
		printf("ARP unsupported HW prot %d\n", hw_prot);
		break;
	}
	//printf("Cmd:");
	switch(ntohs(hdr->ar_op)) {
	case ARPOP_REQUEST:
		//printf("Req");
		break;
	case ARPOP_REPLY:
		//printf("Rep");
		break;
	default:
		printf("ARP unknown opcode:%03X\n", ntohs(hdr->ar_op));
		break;
	}
	return;
}

