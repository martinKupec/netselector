#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <netinet/in.h>
#include <net/ethernet.h>

#include "netscout.h"
#include "network.h"
#include "list.h"

struct llc_snap_header {
	uint8_t dsap;
	uint8_t ssap;
	uint8_t control;
	uint8_t oui[3];
	uint16_t type;
};

struct cdp {
	uint8_t version;
	uint8_t ttl;
	uint16_t checksum;
} cdp;

#define CISCO_DISCOVERY_PROTOCOL	0x2000
#define CISCO_WLCCP					0x0000

#define CDP_DEVICE_ID	0x0001
#define CDP_ADDRESS		0x0002
#define CDP_PORT		0x0003
#define CDP_CAPABILITIES 0x0004
#define CDP_VERSION		0x0005
#define CDP_PLATFORM	0x0006
#define CDP_IPPREFIX	0x0007

void net_snap_cdp(uint8_t *pkt, shell *sh) {
	const struct cdp *p = (const struct cdp *) sh->packet;
	const struct ether_header *hdr = (const struct ether_header *) sh->packet;
	struct stat_cdp *node = NULL;
	char buf[16];
	int len, i;

	if(p->version != 0x01) {
		printf("CDP unknown version %d\n", p->version);
		return;
	}
	pkt += 4;
	while(pkt < (sh->packet + hdr->ether_type)) {
		len = ntohs(*((uint16_t *)(pkt + 2))) ;
		switch(ntohs(*((uint16_t *) (pkt)))) {
			case CDP_DEVICE_ID:
				i = (len - 4) > 16 ? 16 : len - 4;
				memcpy(buf, pkt + 4, i);
				for(; i < 16; i++) {
					buf[i] = ' ';
				}
				node = list_cdp_add_uniq(buf);
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
				break;
			case CDP_PORT:
				if(node && (node->port[0] == '\0')) {
					i = (len - 4) > 10 ? 10 : len - 4;
					memcpy(buf, pkt + 4, i);
					for(; i < 10; i++) {
						buf[i] = ' ';
					}
					memcpy(node->port, buf, 10);
				}
				break;
			case CDP_VERSION:
				if(node && (node->ver[0] == '\0')) {
					i = (len - 4) > 6 ? 6 : len - 4;
					memcpy(buf, pkt + 4, i);
					for(; i < 6; i++) {
						buf[i] = ' ';
					}
					memcpy(node->ver, buf, 6);
				}
				break;
			case CDP_PLATFORM:
				if(node && (node->plat[0] == '\0')) {
					i = (len - 4) > 16 ? 16 : len - 4;
					memcpy(buf, pkt + 4, i);
					for(; i < 16; i++) {
						buf[i] = ' ';
					}
					memcpy(node->plat, buf, 16);
				}
				break;
			default:
				break;
		}
		pkt += len;
	}
}

void net_hndl_snap(const uint8_t *pkt, shell *sh) {
	const struct llc_snap_header *hdr = (const struct llc_snap_header *) pkt;
	uint8_t *payload = ((uint8_t *) (hdr)) + sizeof(struct llc_snap_header);

	switch(ntohs(hdr->type)) {
	case CISCO_DISCOVERY_PROTOCOL:
		net_snap_cdp(payload, sh);
		break;
	case CISCO_WLCCP:
		printf("CISCO Wireless LAN context control protocol\n");
		break;
	default:
		printf("SNAP unknown type %04X\n", hdr->type);
		break;
	}
	return;
}

