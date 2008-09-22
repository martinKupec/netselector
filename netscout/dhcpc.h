
#include <pcap.h>

#define DHCP_TYPE_MESSAGE	53
#define DHCP_TYPE_DISCOVER	1

void dhcpc_offers(pcap_t *hndl, char *interface);

