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
#include "lib/pcap.h"
#include "lib/score.h"
#include "lib/list.h"
#include "lib/wifi.h"
#include "lib/dhcpc.h"
#include "lib/link.h"

struct list list_ether, list_ip, list_wifi;

static unsigned score = 0;
static unsigned score_target = 0;

//static struct stat_ether *list_ether_add_uniq(const uint8_t *mac) {
struct stat_ether *get_node_ether(const uint8_t *mac) {
	return (struct stat_ether *) (list_add_uniq(&list_ether, sizeof(struct stat_ether), mac, 6) );
}

//static struct stat_ip *list_ip_add_uniq(const uint32_t ip) {
struct stat_ip *get_node_ip(const uint32_t ip) {
	return (struct stat_ip *) (list_add_uniq(&list_ip, sizeof(struct stat_ip), (uint8_t *) &ip, 4) );
}

//static struct stat_wifi *list_wifi_add_uniq(const uint8_t *mac) {
struct stat_wifi *get_node_wifi(const uint8_t *mac) {
	return (struct stat_wifi *) (list_add_uniq(&list_wifi, sizeof(struct stat_wifi), mac, 6));
}

bool show_received = true;

static void netscout_score(const unsigned sc) {
	score += sc;
	if(score_target && (score >= score_target)) {
		dispatch_stop();
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
	struct net_pcap np = { .score_fnc = netscout_score };
	bool show_stats = 0;
	bool dhcp_active = 0;
	char *wifidev = NULL;
	
	while ((opt = getopt(argc, argv, "hspw:f:i:dt::")) >= 0) {
		switch(opt) {
		case 'w':
			wifidev = optarg;
			break;
		case 'f':
			np.file = optarg;
			break;
		case 'i':
			np.dev = optarg;
			break;
		case 'd':
			dhcp_active = 1;
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

	ret = pcap_init(&np);
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
		fprintf(stderr, "No device or file specified\n");
		usage();
		return 1;
	case 4:
		fprintf(stderr, "Unknown datalink\n");
		return 1;
	case 5:
		fprintf(stderr, "Unable to register module pcap\n");
		return 1;
	}

	if(wifidev) {
		ret = wifi_init(wifidev, netscout_score);
		switch(ret) {
		case 1:
			perror("Couldn't open wifi socket: ");
			return 2;
		case 2:
			fprintf(stderr, "Unable to register module wifi\n");
			return 2;
		}
	}
	if(dhcp_active) {
		if(!np.dev) {
			fprintf(stderr, "Active DHCP is not possible on file\n");
		} else {
			ret = dhcpc_init(np.hndl, np.dev);
			switch(ret) {
			case 1:
				perror("Random generator error: ");
				return 3;
			case 2:
				perror("Unable to resolv HW address: ");
				return 3;
			case 3:
				fprintf(stderr, "Unable to register module dhcpc\n");
				return 3;
			}
		}
	}

	(void) dispatch_loop();

	if(show_stats) {
		printf("\nStatistics:\n");
		statistics_eth_based();
		if(wifidev) {
			statistics_wifi_based();
		}
	}
	printf("\n");
	return 0;
}

