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

typedef unsigned (*hndl_p)(const uint8_t *pkt, shell *sh);

struct list list_ether, list_ip, list_wifi;

static volatile int signal_stop = 1;

static uint64_t start_time;
static unsigned score = 0;

static struct stat_ether *list_ether_add_uniq(const uint8_t *mac) {
	return (struct stat_ether *) (list_add_uniq(&list_ether, sizeof(struct stat_ether), mac, 6) );
}

static struct stat_ip *list_ip_add_uniq(const uint32_t ip) {
	return (struct stat_ip *) (list_add_uniq(&list_ip, sizeof(struct stat_ip), (uint8_t *) &ip, 4) );
}

static struct stat_wifi *list_wifi_add_uniq(const uint8_t *mac) {
	return (struct stat_wifi *) (list_add_uniq(&list_wifi, sizeof(struct stat_wifi), mac, 6));
}

/*
 * Sets datalink handler for datalink type
 */
static hndl_p set_datalink(const int link) {
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
	const hndl_p hndl = (const hndl_p) args;
	const uint64_t now = hdr->ts.tv_sec * 1000 + (hdr->ts.tv_usec / 1000);
	shell sh;

	sh.time = (uint32_t)(now - start_time);
	sh.packet = pkt;
	score += hndl((const uint8_t *) pkt, &sh);
}

/*
 * Signal handler for terminating
 */
static void signal_hndl(int sig UNUSED) {
	signal_stop = 0;
	signal(SIGINT, SIG_DFL);
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
	char errbuf[PCAP_ERRBUF_SIZE];
	hndl_p datalink_hndl;
	pcap_t *pcap_hndl;
	int dlink, opt;
	struct timeval time;
	char *dev = NULL;
	char *file = NULL;
	char *wifidev = NULL;
	bool dhcp_active = 0;
	bool promiscuous = 0;
	bool show_stats = 0;
	unsigned score_target = 0;
	
	while ((opt = getopt(argc, argv, "hspw:f:i:dt::")) >= 0) {
		switch(opt) {
		case 'w':
			wifidev = optarg;
			break;
		case 'f':
			file = optarg;
			break;
		case 'i':
			dev = optarg;
			break;
		case 'd':
			dhcp_active = 1;
			break;
		case 'p':
			promiscuous = 1;
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

	signal(SIGINT, signal_hndl);

	if(file) {
		printf("File: %s\n", file);
		pcap_hndl = pcap_open_offline(file, errbuf);

		if (pcap_hndl == NULL) {
			fprintf(stderr, "Couldn't open file %s: %s\n", file, errbuf);
			return 2;
		}
	} else if(dev) {
		printf("Device: %s\n", dev);

		pcap_hndl = pcap_open_live(dev, BUFSIZ, promiscuous, 250, errbuf);
		if (pcap_hndl == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return 2;
		}
	} else {
		usage();
		return 1;
	}

	dlink = pcap_datalink(pcap_hndl);
	if(!(datalink_hndl = set_datalink(dlink))) {
		fprintf(stderr, "Don't know datalink type %d\n", dlink);
		return 2;
	}

	gettimeofday(&time, NULL);
	start_time = time.tv_sec * 1000 + (time.tv_usec / 1000);

	if(!file && wifidev) {
		if(wifi_scan_init(wifidev) > 0) {
			fprintf(stderr, "Wifi scan init error\n");
			return 3;
		}
	}
	if(file) {
		pcap_dispatch(pcap_hndl, -1, catcher, (u_char *) datalink_hndl);
	} else {
		pcap_setnonblock(pcap_hndl, 1, errbuf);
		while(signal_stop && (!score_target || (score < score_target))) {
			int ret;
			fd_set sel;

			if(dev && dhcp_active) {
				dhcpc_offers(pcap_hndl, dev);
			}
			if(wifidev) {
				ret = wifi_scan(start_time);
			} else {
				ret = 0;
			}
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
			if(ret > 0) {
				ret = pcap_dispatch(pcap_hndl, -1, catcher, (u_char *) datalink_hndl);
				if(ret < 0) {
					fprintf(stderr, "pcap_dispatch returned: %d\n", ret);
					return 1;
				}
			}
		}
	}
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

