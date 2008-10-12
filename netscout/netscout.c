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
static unsigned score = 0;
unsigned score_target = 0;

size_t info_data_size(const uint32_t type) {
	switch(type) {
	case ETH_TYPE_IP:
	case ETH_TYPE_ARP:
		return sizeof(struct stat_ip);
	case ETH_TYPE_CDP:
		return sizeof(struct proto_cdp);
	case ETH_TYPE_STP:
		return sizeof(struct proto_stp);
	case IP_TYPE_NBNS:
		return sizeof(struct proto_nbname);
	case IP_TYPE_DHCPS:
		return sizeof(struct proto_dhcp);

	case ETH_TYPE_STP_UNKNOWN:
	case ETH_TYPE_CDP_UNKNOWN:
	case ETH_TYPE_SNAP_UNKNOWN:
	case ETH_TYPE_ARP_UNKNOWN:
	case ETH_TYPE_LLC_UNKNOWN:
	case ETH_TYPE_UNKNOWN:
	case ETH_TYPE_WLCCP:
	case ETH_TYPE_EAP:
	case ETH_TYPE_REVARP:
	case ETH_TYPE_VLAN:
	case IP_TYPE_ICMP:
	case IP_TYPE_TCP:
	case IP_TYPE_UDP:
	case IP_TYPE_SSDP:
	case IP_TYPE_DHCPC:
	case IP_TYPE_UNKNOWN:
	default:
		return 0;
	}
}

int info_cmp(const struct info_field *info, unsigned type, void *data, size_t size) {
	if(info->type != type) {
		if(info->type < type) {
			return -1;
		}
		return 1;
	}
	if(size == 0) {
		if(data != info->data) {
			if(info->data < data) {
				return -1;
			} 
			return 1;
		}
		return 0;
	} 
	return memcmp(info->data, data, size);
}

unsigned node_info_find(const struct info_field *info, const unsigned count, const struct shell_exchange *ex, int *found) {
	const size_t size = info_data_size(ex->higher_type);
	int i = 0, j = count - 1, a, c = 1;

	while(c && (i <= j)) {
		a = (i + j) / 2;
		c = info_cmp(info + a, ex->higher_type, ex->higher_data, size);
		if(c < 0) {
			i = a + 1;
		} else if(c > 0) {
			j = a - 1;
		} 
	}
	if(!c) { //Exact match
		if(found) {
			*found = 1;
		}
		return a;
	}
	if(j < 0) {
		return 0;
	}
	if(i > (count - 1)) {
		return count;
	}
	return i;
}

/*
 * Makes room for info and places it in right place
 */
void node_set_info(const struct shell_exchange *ex, const uint32_t time, const int node_type) {
	void *whole_node = ex->lower_node;
	struct pseudo_node *node;
	unsigned here;
	int found = 0;

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
		node->count = 1;
		here = 0;
	} else {
		here = node_info_find(node->info, node->count, ex, &found);
		if(!found) {
			if((node->count & 0x0F) == 0x0F) { // mod 16 is 0
				node->info = (struct info_field *) realloc(node->info, sizeof(struct info_field) * (node->count + 16));
			}
			if(here != node->count) {
				bcopy(node->info + here, node->info + here + 1, sizeof(struct info_field) * (node->count - here));
			}
			node->count++;
		}
	}
	if(found) {
		node->info[here].time_last = time;
		node->info[here].count++;
		if((ex->higher_type != ETH_TYPE_IP) &&
				(ex->higher_type != ETH_TYPE_ARP) &&
				info_data_size(ex->higher_type)) {
			free(ex->higher_data);
		}
		return;
	}
	node->info[here].type = ex->higher_type;
	node->info[here].data = ex->higher_data;
	node->info[here].time_first = time;
	node->info[here].time_last = time;
	node->info[here].count++;
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
-i <interface>	Ethernet listening on <interface> \n\
-d	Send DHCP Offers\n\
-p  Promiscuous mode\n\
-s  Show statistics\n\
-h  Show this help\n\
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

