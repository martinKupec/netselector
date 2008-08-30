#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <pcap.h>
#include <sys/select.h>

#include "netscout.h"
#include "link.h"
#include "list.h"
#include "wifi.h"
#include "statistics.h"

static void (*link_hndl)(const uint8_t *pkt, shell *sh);
static uint64_t start_time;

struct list list_ether, list_ip, list_nbname, list_cdp, list_stp;

static int signal_stop = 1;

void signal_hndl(int sig UNUSED) {
	signal_stop = 0;
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
	pcap_t *pcap_hndl;
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

	pcap_hndl = pcap_open_live(dev, BUFSIZ, 1, 250, errbuf);
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
	pcap_setnonblock(pcap_hndl, 1, errbuf);
	if(wifi_scan_init() > 0) {
		fprintf(stderr, "Wifi scan init error\n");
		return 3;
	}
	while(signal_stop) {
		fd_set sel;

		ret = wifi_scan();
		if(ret < 0) {
			fprintf(stderr, "Wifi scan error %d %d\n", ret, errno);
			return 4;
		}
		if(ret < 200) {
			ret = 200;
		}
		time.tv_sec = 0;
		time.tv_usec = ret * 1000;

		FD_ZERO(&sel);
		FD_SET(*((int *)(pcap_hndl)), &sel);
		ret = select(*((int *)(pcap_hndl)) + 1, &sel, NULL, NULL, &time);
		printf("Select ret %d\n", ret);
		if(ret > 0) {
			ret = pcap_dispatch(pcap_hndl, -1, catcher, NULL);
			if(ret < 0) {
				printf("pcap_dispatch returned: %d\n", ret);
				return 1;
			}
		}
	}
	printf("\nStatistics:\n");
	statistics_eth_based();
	printf("\n");
	return 0;
}

