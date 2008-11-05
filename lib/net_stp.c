#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

#include "lib/netselector.h"
#include "lib/link.h"

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

#define STP_PROTOCOL_STP	0x0000

#define STP_TYPE_CONFIGURATION	0
#define STP_TYPE_TOPO_CHANGE	1

unsigned net_hndl_stp(const uint8_t *pkt, shell *sh) {
	const struct stp_pkt *stp = (const struct stp_pkt *) pkt;
	struct proto_stp *info;

	sh->to.higher_type = ETH_TYPE_NONE;
	sh->to.higher_data = NULL;

	if(ntohs(stp->protocol) == STP_PROTOCOL_STP) {
		if(stp->version != 0x00) {
			sh->from.higher_type = ETH_TYPE_STP_UNKNOWN;
			sh->from.higher_data = (void *) (STP_UNKNOWN_VERSION | ((uint32_t) stp->version));
			return 0;
		}
		if(stp->type != STP_TYPE_CONFIGURATION) {
			sh->from.higher_type = ETH_TYPE_STP_UNKNOWN;
			sh->from.higher_data = (void *) (STP_UNKNOWN_TYPE | ((uint32_t) stp->type));
			return 0;
		}
		info = stp_getmem();
		memcpy(info->bridge, stp->bridge_id, 8);
		memcpy(info->root, stp->root_id, 8);
		info->port = ntohs(stp->port_id);

		sh->from.higher_type = ETH_TYPE_STP;
		sh->from.higher_data = info;
	} else {
		sh->from.higher_type = ETH_TYPE_STP_UNKNOWN;
		sh->from.higher_data = (void *) (STP_UNKNOWN_PROTOCOL | ((uint32_t) stp->protocol));
	}
	return 0;
}

