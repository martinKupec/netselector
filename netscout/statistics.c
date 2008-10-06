#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "statistics.h"
#include "netscout.h"
#include "network.h"
#include "link.h"
#include "list.h"

static void stats_time(const struct info_field *info, const unsigned count, unsigned space) {
	uint32_t avg;

	while(space < 40) {
		putchar(' ');
		space++;
	}
	if(!count)
		return;
	avg = info[count - 1].time / count; //FIXME - not true anymore
	printf("First %03u.%03u ", SHOW_TIME(info[0].time)); //Probably also not true
	printf("Count %d ", count);
	printf("Avg %03u.%03u\n", SHOW_TIME(avg));
}

void statistics_nbns(const struct proto_nbname *nbname) {
	char buf[17];

	memcpy(buf, nbname->name, 16);
	buf[16] = '\0';
	printf("        Ask's NBName %s ", buf);
}

void statistics_dhcps(const struct proto_dhcp *dhcp) {
		printf("    DHCP Server %d.%d.%d.%d", IPQUAD(dhcp->server_IP));
		printf("        Router %d.%d.%d.%d\n", IPQUAD(dhcp->router_IP));
		printf("        DNS %d.%d.%d.%d %d.%d.%d.%d\n", IPQUAD(dhcp->dnsp), IPQUAD(dhcp->dnss));
		printf("        Mask %d.%d.%d.%d\n", IPQUAD(dhcp->mask));
}

void statistics_ip(const struct stat_ip *nip) {
	unsigned msg, space;

	space = printf("    IP %d.%d.%d.%d", IPQUAD(nip->ip));
	stats_time(nip->info, nip->count, space);

	for(msg = 0; msg < nip->count; msg++) {
		switch(nip->info[msg].type) {
		case IP_TYPE_ICMP:
			printf("Send's ICMP\n");
			break;
		case IP_TYPE_TCP:
			printf("Uses TCP\n");
			break;
		case IP_TYPE_UDP:
			printf("Uses UDP\n");
			break;
		case IP_TYPE_SSDP:
			printf("Send's SSDP\n");
			break;
		case IP_TYPE_NBNS:
			statistics_nbns(nip->info[msg].data);
			break;
		case IP_TYPE_DHCPC:
			printf("DHCP Client\n");
			break;
		case IP_TYPE_DHCPS:
			statistics_dhcps(nip->info[msg].data);
			break;
		case IP_TYPE_UNKNOWN:
			//FIXME
			printf("EEEE\n");
			break;
		}
	}
}

void statistics_stp(const struct proto_stp *stp) {
	printf("    STP Bridge: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", stp->bridge[0],
			stp->bridge[1], stp->bridge[2], stp->bridge[3], stp->bridge[4],
			stp->bridge[5], stp->bridge[6], stp->bridge[7]);

	printf("        Root:   %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n        Port:   %04X\n", stp->root[0],
			stp->root[1], stp->root[2], stp->root[3], stp->root[4], stp->root[5],
			stp->root[6], stp->root[7], stp->port);
}

void statistics_cdp(const struct proto_cdp *cdp) {
	char buf[17];

	memcpy(buf, cdp->did, 16);
	buf[16] = '\0';
	printf("    CDP Device ID %s ", buf);
	memcpy(buf, cdp->port, 10);
	buf[10] = '\0';
	printf("        Port %s\n", buf);
	memcpy(buf, cdp->ver, 6);
	buf[6] = '\0';
	printf("        Version %s\n", buf);
	memcpy(buf, cdp->plat, 16);
	buf[16] = '\0';
	printf("        Platform %s\n", buf);
}

void statistics_eth_based(void) {
	struct stat_ether *neth;
	unsigned msg, space;

	LIST_WALK(neth, &list_ether) {
		space = printf("Ether %02X:%02X:%02X:%02X:%02X:%02X", neth->mac[0], neth->mac[1], neth->mac[2],
				neth->mac[3], neth->mac[4], neth->mac[5]);
		stats_time(neth->info, neth->count, space);
		printf("\n");

		for(msg = 0; msg < neth->count; msg++) {
			switch(neth->info[msg].type) {
			case ETH_TYPE_UNKNOWN:
				//FIXME
				printf("WWWW\n");
				break;
			case ETH_TYPE_SNAP_UNKNOWN:
				//FIXME
				printf("WWWW\n");
				break;
			case ETH_TYPE_LLC_UNKNOWN:
				//FIXME
				printf("WWWW\n");
				break;
			case ETH_TYPE_IP:
				statistics_ip(neth->info[msg].data);
				break;
			case ETH_TYPE_STP:
				statistics_stp(neth->info[msg].data);
				break;
			case ETH_TYPE_STP_UNKNOWN:
				//FIXME
				printf("WWWW\n");
				break;
			case ETH_TYPE_CDP:
				statistics_cdp(neth->info[msg].data);
				break;
			case ETH_TYPE_CDP_UNKNOWN:
				//FIXME
				printf("WWWW\n");
				break;
			case ETH_TYPE_ARP_UNKNOWN:
				//FIXME
				printf("WWWW\n");
				break;
			case ETH_TYPE_REVARP:
				printf("REVARP Send\n");
			case ETH_TYPE_VLAN:
				printf("VLAN Detected\n");
				break;
			case ETH_TYPE_EAP:
				printf("Ask's for EAP Authentification\n");
				break;
			case ETH_TYPE_WLCCP:
				printf("Send's WLCCP\n");
				break;
			}
		}
	}
}

void statistics_wifi_based(void) {
	struct stat_wifi *nwifi;
	unsigned int space, i;
	unsigned int avg;

	LIST_WALK(nwifi, &list_wifi) {
		space = printf("Wifi Essid %s", nwifi->essid);
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

