#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <netinet/in.h>

#include "netscout.h"
#include "network.h"
#include "list.h"

struct eap_pkt {
	//802.1X
	uint8_t version;
	uint8_t type;
	uint16_t length;

	//EAP
	uint8_t eap_code;
	uint8_t eap_id;
	uint16_t eap_length;
	uint8_t eap_type;
} PACKED;

void net_hndl_eap(const uint8_t *pkt, shell *sh) {
	/*const struct eap_pkt *eap = (const struct eap_pkt *) pkt;
	struct stat_eap *node;

	if(eap->version > 2) {
		printf("EAP unknown 802.1X Authentication protocol version %02X\n", eap->version);
		return;
	}
	node = list_eap_add_uniq(eap->bridge_id);
		if(node->ether == NULL) {
			memcpy(node->root, stp->root_id, 8);
			node->port = ntohs(stp->port_id);
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
	} else {
		printf("STP unknown protocol %04X\n", stp->protocol);
	}*/
	return;
}
