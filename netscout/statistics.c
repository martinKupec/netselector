#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "netscout.h"
#include "list.h"

#define SHOW_TIME(time) time / 1000, time % 1000
#define IPQUAD(x) x[0], x[1], x[2], x[3]

void stats_time(uint32_t *time, unsigned int count, unsigned int space) {
	uint32_t avg;

	while(space < 40) {
		putchar(' ');
		space++;
	}
	avg = time[count - 1] / count;
	printf("First %03u.%03u ", SHOW_TIME(time[0]));
	printf("Count %d ", count);
	printf("Avg %03u.%03u\n", SHOW_TIME(avg));
}

static unsigned int search_ether(struct stat_ether **eth, uint32_t count, unsigned int *from, uint8_t *addr) {
	unsigned int i, cmp;

	for(i = *from; i < count; i++) {
		if((cmp = memcmp(eth[i]->addr, addr, 6)) < 0) {
			*from = i + 1;
		} else if(cmp > 0) {
			break;
		}
	}
	return i;
}

static unsigned int search_ip(struct stat_ip **ip, uint32_t count, unsigned int *from, uint8_t *addr) {
	unsigned int i, cmp;

	for(i = *from; i < count; i++) {
		if((cmp = memcmp(ip[i]->addr, addr, 4)) < 0) {
			*from = i + 1;
		} else if(cmp > 0) {
			break;
		}
	}
	return i;
}

void statistics_eth_based(void) {
	struct stat_ether *neth;
	struct stat_ip *nip;
	struct stat_nbname *nnbn;
	struct stat_stp *nstp;
	struct stat_cdp *ncdp;
	struct stat_dhcp *ndhcp;
	unsigned int distinct, to, from, space;

	LIST_WALK(neth, &list_ether) {
		space = printf("Ether %02X:%02X:%02X:%02X:%02X:%02X", neth->addr[0], neth->addr[1], neth->addr[2],
				neth->addr[3], neth->addr[4], neth->addr[5]);
		stats_time(neth->time, neth->time_count, space);
		printf("\n");

		distinct = 0;
		LIST_WALK(nip, &list_ip) {
			from = 0;
			to = search_ether(nip->ether, nip->ether_count, &from, neth->addr);
			if(to == from) {
				continue;
			}
			distinct++;
			space = printf("    IP %d.%d.%d.%d", nip->addr[0], nip->addr[1], nip->addr[2], nip->addr[3]);
			stats_time(nip->time + from, to - from, space);

			LIST_WALK(ndhcp, &list_dhcp) {
				if(!memcmp(ndhcp->ip->addr, nip->addr, 4)) {
					space = printf("    DHCP Server %d.%d.%d.%d", IPQUAD(ndhcp->server_IP));
					while(space < 40) {
						putchar(' ');
						space++;
					}
					printf("At %03u.%03u\n", SHOW_TIME(ndhcp->time));
					printf("        Router %d.%d.%d.%d\n", IPQUAD(ndhcp->router_IP));
					printf("        DNS %d.%d.%d.%d %d.%d.%d.%d\n", IPQUAD(ndhcp->dnsp), IPQUAD(ndhcp->dnss));
					printf("        Mask %d.%d.%d.%d\n", IPQUAD(ndhcp->mask));
				}
			}
			LIST_WALK(nnbn, &list_nbname) {
				char buf[17];
				unsigned int nfrom, nto;

				nfrom = 0;
				nto = search_ip(nnbn->ip, nnbn->ip_count, &nfrom, nip->addr);
				if(nto == nfrom) {
					continue;
				}

				memcpy(buf, nnbn->name, 16);
				buf[16] = '\0';
				space = printf("        Ask's NBName %s ", buf);
				stats_time(nnbn->time + nfrom, nto - nfrom, space);
			}
		}
		if(distinct != 0) {
			putchar('\n');
		}

		distinct = 0;
		LIST_WALK(nstp, &list_stp) {
			from = 0;
			to = search_ether(nstp->ether, nstp->ether_count, &from, neth->addr);
			if(to == from) {
				continue;
			}
			distinct++;
			space = printf("    STP Bridge: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", nstp->bridge[0],
					nstp->bridge[1], nstp->bridge[2], nstp->bridge[3], nstp->bridge[4],
					nstp->bridge[5], nstp->bridge[6], nstp->bridge[7]);
			stats_time(nstp->time + from, to - from, space);

			printf("        Root:   %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n        Port:   %04X\n", nstp->root[0],
					nstp->root[1], nstp->root[2], nstp->root[3], nstp->root[4], nstp->root[5],
					nstp->root[6], nstp->root[7], nstp->port);
		}
		if(distinct != 0) {
			putchar('\n');
		}

		LIST_WALK(ncdp, &list_cdp) {
			char buf[17];

			from = 0;
			to = search_ether(ncdp->ether, ncdp->ether_count, &from, neth->addr);
			if(to == from) {
				continue;
			}
			distinct++;

			memcpy(buf, ncdp->did, 16);
			buf[16] = '\0';
			space = printf("    CDP Device ID %s ", buf);
			stats_time(ncdp->time + from, to - from, space);
			memcpy(buf, ncdp->port, 10);
			buf[10] = '\0';
			printf("        Port %s\n", buf);
			memcpy(buf, ncdp->ver, 6);
			buf[6] = '\0';
			printf("        Version %s\n", buf);
			memcpy(buf, ncdp->plat, 16);
			buf[16] = '\0';
			printf("        Platform %s\n", buf);
		}
		if(distinct != 0) {
			putchar('\n');
		}
	}
}

void statistics_wifi_based(void) {
	struct stat_wifi *nwifi;
	unsigned int space, i;
	unsigned int avg;

	LIST_WALK(nwifi, &list_wifi) {
		space = printf("Wifi Essid %s", nwifi->essid);
		stats_time(nwifi->time, nwifi->quality_count, space);

		printf("        Quality ");
		avg = 0;
		for(i = 0; i < nwifi->quality_count; i++) {
			avg += nwifi->quality[i];
		}

		avg /= nwifi->quality_count;
		printf("First %u ", nwifi->quality[0]);
		printf("Last %u ", nwifi->quality[nwifi->quality_count - 1]);
		printf("Avg %u\n", avg);
		printf("\n");
	}
}

void statistics_offer(void) {

}
