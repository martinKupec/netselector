#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "netscout.h"
#include "statistics.h"
#include "lib/netselector.h"
#include "lib/network.h"
#include "lib/link.h"
#include "lib/list.h"

#define SPACE_SIZE	60

static void stats_time(const struct info_field *info, unsigned space) {

	while(space < SPACE_SIZE) {
		putchar(' ');
		space++;
	}
	printf("First %03u.%03u ", SHOW_TIME(info->time_first));
	printf("Last %03u.%03u ", SHOW_TIME(info->time_last));
	printf("Count %d\n", info->count);
}

void statistics_nbns(const struct info_field *info) {
	const struct proto_nbname *nbname = info->data;
	char buf[17];
	unsigned space;

	memcpy(buf, nbname->name, 16);
	buf[16] = '\0';
	space = printf("        Ask's NBName %s", buf);
	stats_time(info, space);
}

unsigned statistics_dhcps(const struct info_field *info, bool oneline) {
	const struct proto_dhcp *dhcp = info->data;
	unsigned space;

	if(!oneline) {
		printf("        ");
	}
	space = printf("DHCP %d.%d.%d.%d", IPQUAD(dhcp->server_IP));
	if(oneline) {
		return space;
	} else {
		stats_time(info, space + 8);
		printf("            Router %d.%d.%d.%d\n", IPQUAD(dhcp->router_IP));
		printf("            DNS %d.%d.%d.%d %d.%d.%d.%d\n", IPQUAD(dhcp->dnsp), IPQUAD(dhcp->dnss));
		printf("            Mask %d.%d.%d.%d\n", IPQUAD(dhcp->mask));
		return 0;
	}
}

void statistics_ip(const struct info_field *info) {
	const struct stat_ip *nip = info->data;
	unsigned msg, space;

	space = printf("    IP %d.%d.%d.%d", IPQUAD(nip->ip));
	stats_time(info, space);

	for(msg = 0; msg < nip->count; msg++) {
		space = 0;
		switch(nip->info[msg].type) {
		case IP_TYPE_ARP:
			space = printf("        Ask's ARP");
			break;
		case IP_TYPE_ICMP:
			space = printf("        Send's ICMP");
			break;
		case IP_TYPE_TCP:
			space = printf("        Send's TCP");
			break;
		case IP_TYPE_UDP:
			space = printf("        Send's UDP port from %d port to %d",
					((uint32_t)(nip->info[msg].data)) >> 16, ((uint32_t)(nip->info[msg].data)) & 0xFFFF);
			break;
		case IP_TYPE_SSDP:
			space = printf("        Send's SSDP");
			break;
		case IP_TYPE_NBNS:
			statistics_nbns(nip->info + msg);
			break;
		case IP_TYPE_DHCPC:
			space = printf("        DHCP Client");
			break;
		case IP_TYPE_DHCPS:
			statistics_dhcps(nip->info + msg, 0);
			break;
		case IP_TYPE_UNKNOWN:
			space = printf("        Send's IP packet with protocol %d", (uint32_t)(nip->info[msg].data));
			break;
		case IP_TYPE_DNSS:
			space = printf("        Send's DNS - Server");
			break;
		case IP_TYPE_DNSC:
			space = printf("        Send's DNS - Client");
			break;
		}
		if(space != 0) {
			stats_time(nip->info + msg, space);
		}
	}
}

unsigned statistics_stp(const struct info_field *info, bool oneline) {
	const struct proto_stp *stp = info->data;
	unsigned space;

	if(!oneline) {

		space = printf("    STP Bridge: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", stp->bridge[0],
				stp->bridge[1], stp->bridge[2], stp->bridge[3], stp->bridge[4],
				stp->bridge[5], stp->bridge[6], stp->bridge[7]);
		stats_time(info, space);
		printf("        ");
	}
	space = printf("Root: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", stp->root[0],
		stp->root[1], stp->root[2], stp->root[3], stp->root[4], stp->root[5],
		stp->root[6], stp->root[7]);
	if(!oneline) {
		printf("\n        Port: %04X\n", stp->port);
		return 0;
	} else {
		return space + printf(" Port:%04X", stp->port);
	}
}

unsigned statistics_cdp(const struct info_field *info, bool oneline) {
	const struct proto_cdp *cdp = info->data;
	unsigned space = 0;

	if(oneline) {
		return printf("CDP %s Port %s", cdp->did, cdp->port);
	} else {
		space = printf("    CDP Device ID %s ", cdp->did);
		stats_time(info, space);
		printf("        Port %s\n        Version %s\n        Platform %s\n", cdp->port, cdp->ver, cdp->plat);;
	}
	return 0;
}

void statistics_eth_based(void) {
	struct stat_ether *neth;
	unsigned msg, space;

	LIST_WALK(neth, &list_ether) {
		printf("Ether %02X:%02X:%02X:%02X:%02X:%02X\n", neth->mac[0], neth->mac[1], neth->mac[2],
				neth->mac[3], neth->mac[4], neth->mac[5]);
		for(msg = 0; msg < neth->count; msg++) {
			space = 0;
			switch(neth->info[msg].type) {
			case ETH_TYPE_UNKNOWN:
				space = printf("    Send's ethernet packet of type %04X", (uint32_t) (neth->info[msg].data));
				break;
			case ETH_TYPE_SNAP_UNKNOWN:
				space = printf("    Send's SNAP packet of type %04X", (uint32_t) (neth->info[msg].data));
				break;
			case ETH_TYPE_LLC_UNKNOWN:
				space = printf("    Send's Ethernet LLC packet from %d to %d",
						((uint32_t) (neth->info[msg].data) ) & 0xFF, (((uint32_t) (neth->info[msg].data)) >> 8) & 0xFF);
				break;
			case ETH_TYPE_IP:
				statistics_ip(neth->info + msg);
				break;
			case ETH_TYPE_STP:
				statistics_stp(neth->info + msg, 0);
				break;
			case ETH_TYPE_STP_UNKNOWN:
				switch(((uint32_t) neth->info[msg].data) & 0xFF00) {
				case STP_UNKNOWN_PROTOCOL:
					space = printf("    Send's STP packet with protocol %d", ((uint32_t) (neth->info[msg].data)) & 0xFF);
					break;
				case STP_UNKNOWN_VERSION:
					space = printf("    Send's STP packet with version %d", ((uint32_t) (neth->info[msg].data)) & 0xFF);
					break;
				case STP_UNKNOWN_TYPE:
					space = printf("    Send's STP packet with type %d", ((uint32_t) (neth->info[msg].data)) & 0xFF);
					break;
				}
				break;
			case ETH_TYPE_CDP:
				statistics_cdp(neth->info + msg, 0);
				break;
			case ETH_TYPE_CDP_UNKNOWN:
				space = printf("    Send's CDP packet of version %d", (uint32_t) (neth->info[msg].data));
				break;
			case ETH_TYPE_ARP_UNKNOWN:
				space = printf("Send's ARP packet with HW prot %d", (uint32_t) (neth->info[msg].data));
				break;
			case ETH_TYPE_REVARP:
				space = printf("    REVARP Detected");
			case ETH_TYPE_VLAN:
				space = printf("    VLAN Detected");
				break;
			case ETH_TYPE_EAP:
				space = printf("    Ask's for EAP Authentification");
				break;
			case ETH_TYPE_WLCCP:
				space = printf("    Send's WLCCP");
				break;
			}
			if(space != 0) {
				stats_time(neth->info + msg, space);
			}
		}
	}
}

void statistics_wifi_based(void) {
	struct stat_wifi *nwifi;
	unsigned int space, i;
	unsigned int avg;

	LIST_WALK(nwifi, &list_wifi) {
		space = printf("Wifi Essid %s count %d\n", nwifi->essid, nwifi->count);
		//stats_time(nwifi->time, nwifi->_count, space);

		printf("        Quality ");
		avg = 0;
		for(i = 0; i < nwifi->count; i++) {
			avg += nwifi->quality[i];
		}

		avg /= nwifi->count;
		printf("First %u ", nwifi->quality[0]);
		printf("Last %u ", nwifi->quality[nwifi->count - 1]);
		printf("Avg %u\n", avg);
		printf("\n");
	}
}

