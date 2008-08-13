#include <stdio.h>
#include <stdint.h>
#include <signal.h>

#include <pcap.h>

#include "netscout.h"
#include "link.h"

static pcap_t *pcap_hndl;
static void (*link_hndl)(const uint8_t *pkt);
static uint64_t start_time;

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
	//printf("%04llu.%03llu Len:%03u ", (now - start_time) / 1000000, ((now - start_time) / 1000) % 1000, hdr->len);
	link_hndl((uint8_t *) pkt);
	//printf("\n");
}

int main(int argc, char *argv[])
{
	char *dev = "eth2";
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret, dlink;
	struct timeval time;

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
	return 0;
}

