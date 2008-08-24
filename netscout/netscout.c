#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#include "netscout.h"
#include "link.h"
#include "list.h"
#include "wifi.h"
#include "statistics.h"

static pcap_t *pcap_hndl;
static void (*link_hndl)(const uint8_t *pkt, shell *sh);
static uint64_t start_time;

struct list list_ether, list_ip, list_nbname, list_cdp, list_stp;

void signal_hndl(int sig UNUSED) {
	pcap_breakloop(pcap_hndl);
	signal(SIGINT, SIG_DFL);
}

int set_datalink(int link) {
	switch(link) {
	case DLT_EN10MB:
		link_hndl = link_hndl_ether;
		break;
	default:
		return 1;
	}
		return 0;
}

void catcher(u_char *args UNUSED, const struct pcap_pkthdr *hdr, const u_char *pkt) {
	uint64_t now = hdr->ts.tv_sec * 1000 + (hdr->ts.tv_usec / 1000);

	shell sh;
	sh.time = (uint32_t)(now - start_time);
	sh.packet = pkt;
	sh.lower_from = NULL;
	sh.lower_to = NULL;
	link_hndl((uint8_t *) pkt, &sh);
}

int main(int argc, char *argv[])
{
	char *dev = "eth2";
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret, dlink, i;
	struct timeval time;
	//struct stat_ether *n;
	//struct stat_ip *lip;
	//struct stat_nbname *lnbn;
	struct stat_cdp *lcdp;
	struct stat_stp *lstp;

	list_init(&list_ether);
	list_init(&list_ip);
	list_init(&list_nbname);
	list_init(&list_cdp);
	list_init(&list_stp);

	printf("Device: %s\n", dev);

	pcap_hndl = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (pcap_hndl == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 1;
	}
	signal(SIGINT, signal_hndl);

	dlink = pcap_datalink(pcap_hndl);
	if(set_datalink(dlink)) {
		fprintf(stderr, "Don't know datalink type %d\n", dlink);
		return 2;
	}
	gettimeofday(&time, NULL);
	start_time = time.tv_sec * 1000 + (time.tv_usec / 1000);
	printf("Wifi scan %d\n", wifi_scan());
	ret = pcap_loop(pcap_hndl, -1, catcher, NULL); //Need to edit to support scanning/timeouts
	//Suggestion - change timeouts to wait time and engage single blocking read, after that we can scan and do it again
	printf("pcap_loop returned: %d\n", ret);
	stats_ether(&list_ether);
	stats_ip(&list_ip);
	/*LIST_WALK(lnbn, &list_nbname) {
		char buf[17];
		uint8_t *last[4];

		memcpy(buf, lnbn->name, 16);
		buf[16] = '\0';
		printf("NBName %s ", buf);

		bzero(last, 4);
		for(i = 0; i < lnbn->ip_count; i++) {
			if(memcmp(lnbn->ip[i]->addr, last, 4)) {
				memcpy(last, lnbn->ip[i]->addr, 4);
				printf("%d.%d.%d.%d %03u.%03u ", lnbn->ip[i]->addr[0],
						lnbn->ip[i]->addr[1], lnbn->ip[i]->addr[2], lnbn->ip[i]->addr[3],
						*(lnbn->time[i]) / 1000000, (*(lnbn->time[i]) / 1000) % 1000);
			} else {
				printf("%03u.%03u ", *(lnbn->time[i]) / 1000000, (*(lnbn->time[i]) / 1000) % 1000);
			}
		}
		printf("\n");
	}*/
	LIST_WALK(lcdp, &list_cdp) {
		char buf[17];
		uint8_t *last[6];

		memcpy(buf, lcdp->did, 16);
		buf[16] = '\0';
		printf("DevID %s ", buf);
		memcpy(buf, lcdp->port, 10);
		buf[10] = '\0';
		printf("Port %s ", buf);
		memcpy(buf, lcdp->ver, 6);
		buf[6] = '\0';
		printf("Ver %s ", buf);
		memcpy(buf, lcdp->plat, 16);
		buf[16] = '\0';
		printf("Plat %s ", buf);

		bzero(last, 6);
		for(i = 0; i < lcdp->ether_count; i++) {
			if(memcmp(lcdp->ether[i]->addr, last, 6)) {
				memcpy(last, lcdp->ether[i]->addr, 6);
				printf("%02X:%02X:%02X:%02X:%02X:%02X %03u.%03u ", lcdp->ether[i]->addr[0],
						lcdp->ether[i]->addr[1], lcdp->ether[i]->addr[2], lcdp->ether[i]->addr[3],
						lcdp->ether[i]->addr[4], lcdp->ether[i]->addr[5],
						lcdp->time[i] / 1000, lcdp->time[i] % 1000);
			} else {
				printf("%03u.%03u ", lcdp->time[i] / 1000, lcdp->time[i] % 1000);
			}
		}
		printf("\n");
	}
	printf("\n");
	LIST_WALK(lstp, &list_stp) {
		uint8_t *last[6];

		printf("Root: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X Bridge:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X Port:%04X ",
			lstp->root[0], lstp->root[1], lstp->root[2], lstp->root[3], lstp->root[4], lstp->root[5], lstp->root[6], lstp->root[7],
			lstp->bridge[0], lstp->bridge[1], lstp->bridge[2], lstp->bridge[3], lstp->bridge[4], lstp->bridge[5], lstp->bridge[6],
			lstp->bridge[7], lstp->port);

		bzero(last, 6);
		for(i = 0; i < lstp->ether_count; i++) {
			if(memcmp(lstp->ether[i]->addr, last, 6)) {
				memcpy(last, lstp->ether[i]->addr, 6);
				printf("%02X:%02X:%02X:%02X:%02X:%02X %03u.%03u ", lstp->ether[i]->addr[0],
						lstp->ether[i]->addr[1], lstp->ether[i]->addr[2], lstp->ether[i]->addr[3],
						lstp->ether[i]->addr[4], lstp->ether[i]->addr[5],
						lstp->time[i] / 1000, lstp->time[i] % 1000);
			} else {
				printf("%03u.%03u ", lstp->time[i] / 1000, lstp->time[i] % 1000);
			}
		}
		printf("\n");
	}
	return 0;
}

