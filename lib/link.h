#ifndef __LIB_LINK_H__
#define __LIB_LINK_H__

#include <stdint.h>

#include "lib/netselector.h"

#define STP_UNKNOWN_PROTOCOL	0x8000
#define STP_UNKNOWN_VERSION		0x4000
#define STP_UNKNOWN_TYPE		0x2000

unsigned link_hndl_ether(const uint8_t *pkt, shell *sh);

#endif

