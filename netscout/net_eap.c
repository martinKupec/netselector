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
	const struct eap_pkt *eap = (const struct eap_pkt *) pkt;

	ipmisc_add_new(IPMISC_EAP, sh);
	if(eap->version > 2) {
		printf("EAP unknown 802.1X Authentication protocol version %02X\n", eap->version);
	}
	return;
}
