#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <netinet/in.h>

#include "netscout.h"
#include "network.h"
#include "list.h"

struct stp_pkt {
	uint16_t protocol;
	uint8_t version;
	uint8_t type;
	uint8_t flags;
	uint8_t root_id[8];
	uint32_t cost;
	uint8_t bridge_id[8];
	uint16_t port_id;
	uint16_t msg_age;
	uint16_t max_age;
	uint16_t hello_time;
	uint16_t delay;
} PACKED;

#define PROTOCOL_STP	0x0000

#define STP_TYPE_CONFIGURATION	0
#define STP_TYPE_TOPO_CHANGE	1

//const uint8_t stp_multicast_adr[] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00 };
				
void net_hndl_stp(const uint8_t *pkt, shell *sh) {
	const struct stp_pkt *stp = (const struct stp_pkt *) pkt;
	struct stat_stp *node;

	if(ntohs(stp->protocol) == PROTOCOL_STP) {
		if(stp->version != 0x00) {
			printf("STP unknown protocol version %02X\n", stp->version);
			return;
		}
		if(stp->type != STP_TYPE_CONFIGURATION) {
			printf("STP non-configuration packet\n");
			return;
		}

		node = list_stp_add_uniq(stp->bridge_id);
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
	}
	return;
}
