
#include <pcap.h>
#include <stdint.h>

#define DHCP_TYPE_MESSAGE	53
#define DHCP_TYPE_DISCOVER	1
#define DHCP_TYPE_VENDOR_ID	60

void dhcpc_offers(pcap_t *hndl, char *interface);
void dhcpc_packet(const uint8_t *pkt, shell *sh);

