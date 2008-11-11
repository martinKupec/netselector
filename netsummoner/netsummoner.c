#include <stdlib.h>
#include <unistd.h>

#include "netsummoner.h"
#include "lib/netselector.h"
#include "lib/score.h"
#include "lib/list.h"
#include "lib/wifi.h"
#include "lib/dhcpc.h"
#include "lib/link.h"

int yyparse(void);
extern FILE *yyin;

struct list list_network, list_action, list_assembly;

static struct stat_ether ether_node_from, ether_node_to;
static struct stat_ip ip_node_from, ip_node_to;
static struct stat_wifi wifi_node;

static struct stat_ether *list_ether_add(const uint8_t *mac) {
	return &ether_node_to;
}

static struct stat_ip *list_ip_add(const uint32_t ip) {
	return &ip_node_to;
}

static struct stat_wifi *list_wifi_add(const uint8_t *mac) {
	return &wifi_node;
}

static void daemonize(void) {

}

void pcap_callback(const unsigned score) {
	printf("HUH!\n");
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
	libnetselector_init(list_ip_add, list_ether_add, list_wifi_add, 0);

	yyin = fopen("configure", "r");
	if(!yyin) {
		fprintf(stderr, "Unable to open configuration file\n");
		return 1;
	}
	yyparse();

	ret = use_pcap(&np);
	return 0;
}

