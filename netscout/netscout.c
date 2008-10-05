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
#include "dhcpc.h"

struct pseudo_node {
	unsigned count;
	struct info_field *info;
};

struct list list_ether, list_ip, list_wifi;

static volatile int signal_stop = 1;
static uint64_t start_time;

/*
 * Makes room for info and places it in right place
 */
void node_set_info(const struct shell_exchange *ex, const uint32_t time, const int node_type) {
	void *whole_node = ex->lower_node;
	struct pseudo_node *node;
	struct info_field my = {.type = ex->higher_type, .time = time};
	unsigned here;

	switch(node_type) {
	case NODE_TYPE_ETH:
		node = (struct pseudo_node *) &(((struct stat_ether *)(whole_node))->count);
		break;
	case NODE_TYPE_IP:
		node = (struct pseudo_node *) &(((struct stat_ip *)(whole_node))->count);
		break;
	}

	if(node->info == NULL) {
		node->info = (struct info_field *) malloc(sizeof(struct info_field) * 16); 
	} else {
		if((node->count & 0x0F) == 0x0F) { // mod 16 is 0
			node->info = (struct info_field *) realloc(node->info, sizeof(struct info_field) * (node->count + 16));
		}
	}
	if(!node->count) { //Nothing here yet
		here = 0;
	} else if(memcmp(&my, node->info + node->count - 1, sizeof(uint32_t) * 2) > 0) { //Last is before
		here = node->count;
	} else { //Need to put inside
		for(here = 0; here < node->count; here++) {
			if(memcmp(&my, node->info + node->count - 1, sizeof(uint32_t) * 2) > 0) {
				break;
			}
			bcopy(node->info + here, node->info + here + 1, sizeof(struct info_field) * (node->count - here));
		}
	}
	node->info[here].type = ex->higher_type;
	node->info[here].data = ex->higher_data;
	node->info[here].time = time;
}

/*
 * Sets datalink handler for datalink type
 */
static hndl_t *set_datalink(const int link) {
	switch(link) {
	case DLT_EN10MB:
		return link_hndl_ether;
	}
	return NULL;
}

/*
 * Pcap's catcher
 */
static void catcher(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {
	const hndl_t *hndl = (const hndl_t *) args;
	const uint64_t now = hdr->ts.tv_sec * 1000 + (hdr->ts.tv_usec / 1000);
	shell sh;

	sh.time = (uint32_t)(now - start_time);
	sh.packet = pkt;
	hndl((uint8_t *) pkt, &sh);
}

/*
 * Signal handler for terminating
 */
static void signal_hndl(int sig UNUSED) {
	signal_stop = 0;
	signal(SIGINT, SIG_DFL);
}

int main(int argc, char *argv[])
{
	hndl_t *datalink_hndl;
	pcap_t *pcap_hndl;
	char *dev = "eth0";
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret, dlink;
	struct timeval time;

	list_init(&list_ether);
	list_init(&list_ip);
	list_init(&list_wifi);

	printf("Device: %s\n", dev);

	pcap_hndl = pcap_open_live(dev, BUFSIZ, 1, 250, errbuf);
	if (pcap_hndl == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 1;
	}
	signal(SIGINT, signal_hndl);

	dlink = pcap_datalink(pcap_hndl);
	if(!(datalink_hndl = set_datalink(dlink))) {
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
		
		dhcpc_offers(pcap_hndl, dev);
		ret = wifi_scan(start_time);
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
		//printf("Select ret %d\n", ret);
		if(ret > 0) {
			ret = pcap_dispatch(pcap_hndl, -1, catcher, (u_char *) datalink_hndl);
			if(ret < 0) {
				printf("pcap_dispatch returned: %d\n", ret);
				return 1;
			}
		}
	}
	printf("\nStatistics:\n");
	statistics_eth_based();
	statistics_wifi_based();
	printf("\n");
	/*printf("Offers:");
	statistics_offer();*/
	return 0;
}

