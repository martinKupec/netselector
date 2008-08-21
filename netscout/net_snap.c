#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <netinet/in.h>
#include <net/ethernet.h>

#include "netscout.h"
#include "network.h"

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
	char buf[100];
	int len;

	if(p->version != 0x01) {
		printf("CDP unknown version %d\n", p->version);
		return;
	}
	pkt += 4;
	while(pkt < (sh->packet + hdr->ether_type)) {
		len = ntohs(*((uint16_t *)(pkt + 2))) ;
		switch(ntohs(*((uint16_t *) (pkt)))) {
			case CDP_DEVICE_ID: //USE THIS - REST IS USELESS - MAYBE SHOW
				memcpy(buf, pkt + 4, len - 4);
				buf[len - 4] = '\0';
				printf("Device ID %s\n", buf);
				break;
			case CDP_PORT:
				memcpy(buf, pkt + 4, len - 4);
				buf[len - 4] = '\0';
				printf("Port %s\n", buf);
				break;
			case CDP_VERSION:
				memcpy(buf, pkt + 4, len - 4);
				buf[len - 4] = '\0';
				printf("Version %s\n", buf);
				break;
			case CDP_PLATFORM:
				memcpy(buf, pkt + 4, len - 4);
				buf[len - 4] = '\0';
				printf("Platform %s\n", buf);
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

	//printf("SNAP OUI %02X%02X%02X ", hdr->oui[0], hdr->oui[1], hdr->oui[2]);
	switch(ntohs(hdr->type)) {
	case CISCO_DISCOVERY_PROTOCOL:
		net_snap_cdp(payload, sh);
		break;
	default:
		printf("SNAP unknown type %04X\n", hdr->type);
		break;
	}
	return;
}

