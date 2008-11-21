#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "netsummoner.h"
#include "arbiter.h"
#include "lib/netselector.h"
#include "lib/score.h"
#include "lib/list.h"
#include "lib/wifi.h"
#include "lib/dhcpc.h"
#include "lib/link.h"

int yyparse(void);
extern FILE *yyin;

struct list list_network, list_action, list_assembly;

static struct arbiter_queue aqueue;

static struct stat_ether ether_node_from, ether_node_to;
static struct stat_ip ip_node_from, ip_node_to;
static struct stat_wifi wifi_node;

static struct stat_ether *list_ether_add(const uint8_t *mac) {
	if(!aqueue.enode_f) {
		aqueue.enode_f = &ether_node_from;
		memcpy(aqueue.enode_f->mac, mac, 6);
		return aqueue.enode_f;
	} else if(!aqueue.enode_t) {
		aqueue.enode_t = &ether_node_to;
		memcpy(aqueue.enode_t->mac, mac, 6);
		return aqueue.enode_t;
	} else {
		return NULL;
	}
}

static struct stat_ip *list_ip_add(const uint32_t ip) {
	if(!aqueue.inode_f) {
		aqueue.inode_f = &ip_node_from;
		aqueue.inode_f->ip = ip;
		return aqueue.inode_f;
	} else if(!aqueue.inode_t) {
		aqueue.inode_t = &ip_node_to;
		aqueue.inode_t->ip= ip;
		return aqueue.inode_t;
	} else {
		return NULL;
	}
}

static struct stat_wifi *list_wifi_add(const uint8_t *mac) {
	aqueue.wnode = &wifi_node;
	memcpy(aqueue.wnode->mac, mac, 6);
	return &wifi_node;
}

static void daemonize(void) {

}

static void pcap_callback(const unsigned score UNUSED) {
	arbiter(&aqueue);
	bzero(&aqueue, sizeof(struct arbiter_queue));
}

static void usage(void) {
	fprintf(stderr, "Usage: netscout -[i|f] [-w]\n\
-w <interface>	Enable WiFi scanning on <interface>\n\
-f <file>	Use dump file instead of live\n\
-i <interface>	Ethernet listening on <interface>\n\
-d  Send DHCP Offers\n\
-p  Promiscuous mode\n\
-h  Show this help\
\n");
}

int main(int argc, char **argv) {
	int opt, ret;
	struct net_pcap np = { .score_fnc = pcap_callback };
	
	while ((opt = getopt(argc, argv, "hpw:f:i:d")) >= 0) {
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
		case 'h':
		default:
			usage();
			return 1;
		}
	}

	daemonize();

	list_init(&list_network);
	list_init(&list_action);
	list_init(&list_assembly);
	libnetselector_init(list_ip_add, list_ether_add, list_wifi_add, 1);

	yyin = fopen("configure", "r");
	if(!yyin) {
		fprintf(stderr, "Unable to open configuration file\n");
		return 1;
	}
	yyparse();

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

	return 0;
}

