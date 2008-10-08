#ifndef __NETSCOUT_LINK_H__
#define __NETSCOUT_LINK_H__

#include <stdint.h>

#define STP_UNKNOWN_PROTOCOL	0x8000
#define STP_UNKNOWN_VERSION		0x4000
#define STP_UNKNOWN_TYPE		0x2000

void link_hndl_ether(const uint8_t *pkt, shell *sh);

#endif

