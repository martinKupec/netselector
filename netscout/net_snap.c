#include <stdio.h>
#include <stdint.h>

#include <netinet/in.h>

#include "network.h"
#include "netscout.h"

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
};

#define CISCO_DISCOVERY_PROTOCOL	0x2000

void net_snap_cdp(uint8_t *pkt) {
	const struct cdp *p = (const struct cdp *) pkt;

	if(p->version != 0x01) {
		printf("CDP unknown version %d\n", p->version);
		return;
	}
	printf("CDP package got\n"); //FIXME need to known package size to determine variable-sized values
}

void net_hndl_snap(const uint8_t *pkt) {
	const struct llc_snap_header *hdr = (const struct llc_snap_header *) pkt;
	uint8_t *payload = ((uint8_t *) (hdr)) + sizeof(struct llc_snap_header);

	printf("SNAP OUI %02X%02X%02X ", hdr->oui[0], hdr->oui[1], hdr->oui[2]);
	switch(ntohs(hdr->type)) {
	case CISCO_DISCOVERY_PROTOCOL:
		net_snap_cdp(payload);
		break;
	default:
		printf("SNAP unknown type %04X\n", hdr->type);
		break;
	}
	return;
}

