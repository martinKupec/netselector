#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <sys/select.h>

#include "netscout.h"
#include "statistics.h"
#include "lib/netselector.h"
#include "lib/score.h"
#include "lib/list.h"
#include "lib/wifi.h"
#include "lib/dhcpc.h"
#include "lib/link.h"

struct list list_ether, list_ip, list_wifi;

static unsigned score = 0;
static unsigned score_target = 0;

static struct stat_ether *list_ether_add_uniq(const uint8_t *mac) {
	return (struct stat_ether *) (list_add_uniq(&list_ether, sizeof(struct stat_ether), mac, 6) );
}

static struct stat_ip *list_ip_add_uniq(const uint32_t ip) {
	return (struct stat_ip *) (list_add_uniq(&list_ip, sizeof(struct stat_ip), (uint8_t *) &ip, 4) );
}

static struct stat_wifi *list_wifi_add_uniq(const uint8_t *mac) {
	return (struct stat_wifi *) (list_add_uniq(&list_wifi, sizeof(struct stat_wifi), mac, 6));
}

static void pcap_callback(const unsigned sc) {
	score += sc;
	if(score_target && (score >= score_target)) {
		signal_stop = 1;
	}
}

static void usage(void) {
	fprintf(stderr, "Usage: netscout -[i|f] [-w]\n\
-w <interface>	Enable WiFi scanning on <interface>\n\
-f <file>	Use dump file instead of live\n\
-i <interface>	Ethernet listening on <interface>\n\
-d  Send DHCP Offers\n\
-p  Promiscuous mode\n\
-s  Show statistics\n\
-t [<target>] Sets Score target to [<target>] or default\n\
-h  Show this help\
\n");
}

int main(int argc, char **argv) {
	int opt, ret;
	struct net_pcap np = { .score_fnc = pcap_callback };
	bool show_stats = 0;
	
	while ((opt = getopt(argc, argv, "hspw:f:i:dt::")) >= 0) {
		switch(opt) {
		case 'w':
			np.wifidev = optarg;
			break;
		case 'f':
			np.file = optarg;
			break;
		case 'i':
			np.dev = optarg;
			break;
		case 'd':
			np.dhcp_active = 1;
			break;
		case 'p':
			np.promiscuous = 1;
			break;
		case 's':
			show_stats = 1;
			break;
		case 't':
			if(optarg) {
				score_target = atoi(optarg);
			} else {
				score_target = SCORE_TARGET_DEFAULT;
			}
			break;
		case 'h':
		default:
			usage();
			return 1;
		}
	}

	list_init(&list_ether);
	list_init(&list_ip);
	list_init(&list_wifi);
	libnetselector_init(list_ip_add_uniq, list_ether_add_uniq, list_wifi_add_uniq, 1);

	ret = use_pcap(&np);

	switch(ret) {
	case 0:
		break;
	case 1:
		fprintf(stderr, "Couldn't open file %s: %s\n", np.file, np.errbuf);
		return 1;
	case 2:
		fprintf(stderr, "Couldn't open device %s: %s\n", np.dev, np.errbuf);
		return 1;
	case 3:
		usage();
		return 1;
	case 4:
		fprintf(stderr, "Unknown datalink type %d\n", np.err);
		return 1;
	case 5:
		fprintf(stderr, "Wifi scan init error\n");
		return 1;
	case 6:
		fprintf(stderr, "Wifi scan error %d %d\n", np.err, errno);
		return 1;
	case 7:
		fprintf(stderr, "pcap_dispatch returned: %d\n", np.err);
		return 1;
	}

	if(show_stats) {
		printf("\nStatistics:\n");
		statistics_eth_based();
		if(np.wifidev) {
			statistics_wifi_based();
		}
	}
	printf("\n");
	return 0;
}

