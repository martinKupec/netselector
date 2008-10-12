#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <netinet/in.h>
#include <net/ethernet.h>

#include "netscout.h"
#include "link.h"
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

#define SNAP_CDP		0x2000
#define SNAP_WLCCP		0x0000

#define CDP_DEVICE_ID	0x0001
#define CDP_ADDRESS		0x0002
#define CDP_PORT		0x0003
#define CDP_CAPABILITIES 0x0004
#define CDP_VERSION		0x0005
#define CDP_PLATFORM	0x0006
#define CDP_IPPREFIX	0x0007

/*
 * Cisco Discovery Protocol dispatcher
 */
static unsigned net_snap_cdp(const uint8_t *pkt, shell *sh) {
	const struct cdp *p = (const struct cdp *) pkt;
	const struct ether_header *hdr = (const struct ether_header *) sh->packet;
	struct proto_cdp *info;

	if(p->version != 0x01) {
		sh->from.higher_type = ETH_TYPE_CDP_UNKNOWN;
		sh->from.higher_data = (void *) ((uint32_t) p->version);
		sh->to.higher_type = ETH_TYPE_NONE;
		sh->to.higher_data = NULL;
		return SCORE_CDP_UNKNOWN;
	}
	info = cdp_getmem();
	bzero(info, sizeof(proto_cdp));

	pkt += sizeof(struct cdp);
	while(pkt < (sh->packet + hdr->ether_type)) {
		uint16_t len, type;
		int i;

		type = ntohs(*((uint16_t *) (pkt)));
		len = ntohs(*((uint16_t *)(pkt + 2))) ;
		switch(type) {
			case CDP_DEVICE_ID:
				i = (len - 4) > 16 ? 16 : len - 4;
				memcpy(info->did, pkt + 4, i);
				for(; i < 16; i++) {
					info->did[i] = ' ';
				}
				break;
			case CDP_PORT:
				i = (len - 4) > 10 ? 10 : len - 4;
				memcpy(info->port, pkt + 4, i);
				for(; i < 10; i++) {
					info->port[i] = ' ';
				}
				break;
			case CDP_VERSION:
				i = (len - 4) > 6 ? 6 : len - 4;
				memcpy(info->ver, pkt + 4, i);
				for(; i < 6; i++) {
					info->ver[i] = ' ';
				}
				break;
			case CDP_PLATFORM:
				i = (len - 4) > 16 ? 16 : len - 4;
				memcpy(info->plat, pkt + 4, i);
				for(; i < 16; i++) {
					info->plat[i] = ' ';
				}
				break;
			default:
				break;
		}
		pkt += len;
	}
	sh->from.higher_type = ETH_TYPE_CDP;
	sh->from.higher_data = info;
	sh->to.higher_type = ETH_TYPE_NONE;
	sh->to.higher_data = NULL;
	return SCORE_CDP;
}

/*
 * Basic SNAP handler
 */
unsigned net_hndl_snap(const uint8_t *pkt, shell *sh) {
	const struct llc_snap_header *hdr = (const struct llc_snap_header *) pkt;
	const uint8_t *payload = ((const uint8_t *) (hdr)) + sizeof(struct llc_snap_header);
	const uint16_t snap_type = ntohs(hdr->type);
	unsigned score = 0;

	switch(snap_type) {
	case SNAP_CDP:
		score = net_snap_cdp(payload, sh);
		break;
	case SNAP_WLCCP:
		sh->from.higher_type = ETH_TYPE_WLCCP;
		sh->from.higher_data = NULL;
		sh->to.higher_type = ETH_TYPE_NONE;
		sh->to.higher_data = NULL;
		score = SCORE_WLCCP;
		break;
	default:
		sh->from.higher_type = ETH_TYPE_SNAP_UNKNOWN;
		sh->from.higher_data = (void *) ((uint32_t) snap_type);
		sh->to.higher_type = ETH_TYPE_NONE;
		sh->to.higher_data = NULL;
		score = SCORE_SNAP_UNKNOWN;
		break;
	}
	return score;
}

