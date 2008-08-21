#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#include "netscout.h"
#include "link.h"
#include "list.h"

static pcap_t *pcap_hndl;
static void (*link_hndl)(const uint8_t *pkt, shell *sh);
static uint64_t start_time;

struct list list_ether, list_ip, list_nbname;

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
	uint64_t now = hdr->ts.tv_sec * 1000000 + hdr->ts.tv_usec;

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
	struct stat_nbname *lnbn;

	list_init(&list_ether);
	list_init(&list_ip);
	list_init(&list_nbname);

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
	start_time = time.tv_sec * 1000000 + time.tv_usec;
	ret = pcap_loop(pcap_hndl, -1, catcher, NULL);
	printf("pcap_loop returned: %d\n", ret);
	/*LIST_WALK(n, &list_ether) {
		printf("Ether %02X:%02X:%02X:%02X:%02X:%02X ", n->addr[0], n->addr[1], n->addr[2], n->addr[3], n->addr[4], n->addr[5]);
		for(i = 0; i < n->time_count; i++) {
			printf("%03u.%03u ", n->time[i] / 1000000, (n->time[i] / 1000) % 1000);
		}
		printf("\n");
	}*/
	/*LIST_WALK(lip, &list_ip) {
		uint8_t last[6];

		printf("IP %d.%d.%d.%d ", lip->addr[0], lip->addr[1], lip->addr[2], lip->addr[3]);
		bzero(last, 6);
		for(i = 0; i < lip->ether_count; i++) {
			if(memcmp(lip->ether[i]->addr, last, 6)) {
				memcpy(last, lip->ether[i]->addr, 6);
				printf("%02X:%02X:%02X:%02X:%02X:%02X %03u.%03u ", lip->ether[i]->addr[0],
						lip->ether[i]->addr[1], lip->ether[i]->addr[2], lip->ether[i]->addr[3],
						lip->ether[i]->addr[4], lip->ether[i]->addr[5],
						*(lip->time[i]) / 1000000, (*(lip->time[i]) / 1000) % 1000);
			} else {
				printf("%03u.%03u ", *(lip->time[i]) / 1000000, (*(lip->time[i]) / 1000) % 1000);
			}
		}
		printf("\n");
	}*/
	LIST_WALK(lnbn, &list_nbname) {
		char buf[17];
		uint8_t *last[4];

		memcpy(buf, lnbn->name, 16);
		buf[16] = '\0';
		printf("NBName %s ", buf);

		bzero(last, 6);
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
	}
	return 0;
}

