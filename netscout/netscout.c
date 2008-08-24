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
	int ret, dlink;
	struct timeval time;

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
	//printf("Wifi scan %d\n", wifi_scan());
	ret = pcap_loop(pcap_hndl, -1, catcher, NULL); //Need to edit to support scanning/timeouts
	//Suggestion - change timeouts to wait time and engage single blocking read, after that we can scan and do it again
	if((ret < 0) && (ret != -2)) {
		printf("pcap_loop returned: %d\n", ret);
		return 1;
	}
	printf("\nStatistics:\n");
	statistics_eth_based();
	printf("\n");
	return 0;
}

