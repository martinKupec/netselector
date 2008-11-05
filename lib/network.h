#ifndef __LIB_NETWORK_H__
#define __LIB_NETWORK_H__

#include <stdint.h>

#include "lib/netselector.h"

unsigned net_hndl_arp(const uint8_t *pkt, shell *sh);
unsigned net_hndl_stp(const uint8_t *pkt, shell *sh);
unsigned net_hndl_snap(const uint8_t *pkt, shell *sh);
unsigned net_hndl_ip(const uint8_t *pkt, shell *sh);
unsigned net_hndl_eap(const uint8_t *pkt, shell *sh);
unsigned net_hndl_nbns(const uint8_t *pkt, shell *sh);

#endif

