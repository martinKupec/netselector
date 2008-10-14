#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <netinet/in.h>

#include "netscout.h"
#include "link.h"
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

unsigned net_hndl_eap(const uint8_t *pkt, shell *sh) {
	const struct eap_pkt *eap = (const struct eap_pkt *) pkt;

	sh->from.higher_type = ETH_TYPE_EAP;
	sh->from.higher_data = (void *) ((uint32_t)( eap->version));
	sh->to.higher_type = ETH_TYPE_NONE;
	sh->to.higher_data = NULL;
	return 0;
}
