#ifndef __NETSCOUT_NETWORK_H__
#define __NETSCOUT_NETWORK_H__

#include <stdint.h>

enum {
	IP_TYPE_NONE,
	IP_TYPE_ICMP,
	IP_TYPE_TCP,
	IP_TYPE_UDP,
	IP_TYPE_SSDP,
	IP_TYPE_NBNS,
	IP_TYPE_DHCPC,
	IP_TYPE_DHCPS,
	IP_TYPE_UNKNOWN,
	IP_TYPE_LAST
};

#define UDP_PORT_NBNS	137
#define UDP_PORT_DHCPS	68
#define UDP_PORT_DHCPC	67
#define UDP_PORT_SSDP	1900

void net_hndl_arp(const uint8_t *pkt, shell *sh);
void net_hndl_stp(const uint8_t *pkt, shell *sh);
void net_hndl_snap(const uint8_t *pkt, shell *sh);
void net_hndl_ip(const uint8_t *pkt, shell *sh);
void net_hndl_eap(const uint8_t *pkt, shell *sh);
void net_hndl_nbns(const uint8_t *pkt, shell *sh);

#endif

