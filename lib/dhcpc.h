#ifndef __LIB_DHCPC_H__
#define __LIB_DHCPC_H__

#include <pcap.h>
#include <stdint.h>

#define BOOTPREQUEST	1
#define BOOTPRESPONCE	2

#define DHCP_DISCOVER	1
#define DHCP_OFFER		2

#define DHCP_TYPE_PAD		0
#define DHCP_TYPE_MASK		1
#define DHCP_TYPE_ROUTER	3
#define DHCP_TYPE_DNS		6
#define DHCP_TYPE_DOMAIN_NAME	17
#define DHCP_TYPE_MESSAGE	53
#define DHCP_TYPE_SERVER_ID	54
#define DHCP_TYPE_VENDOR_ID	60
#define DHCP_TYPE_END		255

#define BOOTPS_PORT	67
#define BOOTPC_PORT 68

void dhcpc_offers(pcap_t *hndl, const char *interface);
void dhcpc_packet(const uint8_t *pkt, shell *sh);

#endif

