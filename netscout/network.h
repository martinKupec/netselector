#ifndef __NETSCOUT_NETWORK_H__
#define __NETSCOUT_NETWORK_H__

#include <stdint.h>

void net_hndl_arp(const uint8_t *pkt, shell *sh);
void net_hndl_stp(const uint8_t *pkt, shell *sh);
void net_hndl_snap(const uint8_t *pkt, shell *sh);
void net_hndl_ip(const uint8_t *pkt, shell *sh);
void net_hndl_eap(const uint8_t *pkt, shell *sh);
void net_hndl_nbns(const uint8_t *pkt, shell *sh);

#endif

