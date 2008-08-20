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

struct list list_ether, list_ip;

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
	struct stat_ether *n;

	list_init(&list_ether);

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
	//filter_list(&list_ether, 0, 6);
	LIST_WALK(n, &list_ether) {
		printf("Ether %02X:%02X:%02X:%02X:%02X:%02X ", n->addr[0], n->addr[1], n->addr[2], n->addr[3], n->addr[4], n->addr[5]);
		for(i = 0; i < n->time_count; i++) {
			printf("%03u.%03u ", n->time[i] / 1000000, (n->time[i] / 1000) % 1000);
		}
		printf("\n");
	}
	return 0;
}

