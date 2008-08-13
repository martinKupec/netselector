#include <stdio.h>
#include <stdint.h>

#include <netinet/in.h>

#include "network.h"
#include "netscout.h"

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
				
void net_hndl_stp(const uint8_t *pkt) {
	const struct stp_pkt *stp = (const struct stp_pkt *) pkt;
	switch(stp->protocol) {
	case PROTOCOL_STP:
		if(stp->version != 0x00) {
			printf("STP unknown protocol version %02X\n", stp->version);
			break;
		}
		if(stp->type != STP_TYPE_CONFIGURATION) {
			printf("STP non-configuration packet\n");
			break; 
		}
		//FIXME use root id to identify network - bridge id for network part & port
		/*printf("Root: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X Bridge:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X ",
			stp->root_id[0],
			stp->root_id[1],
			stp->root_id[2],
			stp->root_id[3],
			stp->root_id[4],
			stp->root_id[5],
			stp->root_id[6],
			stp->root_id[7],
			stp->bridge_id[0],
			stp->bridge_id[1],
			stp->bridge_id[2],
			stp->bridge_id[3],
			stp->bridge_id[4],
			stp->bridge_id[5],
			stp->bridge_id[6],
			stp->bridge_id[7]
			);*/
		break;
	default:
		printf("STP unknown protocol %04X\n", stp->protocol);
		break;
	}
	return;
}
