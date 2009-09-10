#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "netsummoner.h"
#include "arbiter.h"
#include "execute.h"
#include "wpa.h"
#include "lib/netselector.h"
#include "lib/pcap.h"
#include "lib/score.h"
#include "lib/list.h"
#include "lib/wifi.h"
#include "lib/dhcpc.h"
#include "lib/link.h"
#include "netlink.h"

#define NETSUM_EXIT	((void *)(0))
#define NETSUM_DELAYED	((void *)(1))

int yyparse(void);
extern FILE *yyin;

bool show_received;
unsigned int wait_seconds = 0;

struct list list_network, list_action, list_assembly;

static struct arbiter_queue aqueue;
static bool connection, exit_on_connection, abort_on_timeout;

static struct stat_ether ether_node_from, ether_node_to;
static struct stat_ip ip_node_from, ip_node_to;
static struct stat_wifi wifi_node;

static struct module_info module_netsummoner;

//static struct stat_ether *list_ether_add(const uint8_t *mac) {
struct stat_ether *get_node_ether(const uint8_t *mac) {
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

//static struct stat_ip *list_ip_add(const uint32_t ip) {
struct stat_ip *get_node_ip(const uint32_t ip) {
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

//static struct stat_wifi *list_wifi_add(const uint8_t *mac) {
struct stat_wifi *get_node_wifi(const uint8_t *mac) {
	aqueue.wnode = &wifi_node;
	memcpy(aqueue.wnode->mac, mac, 6);
	return &wifi_node;
}

static void daemonize(void) {

}

static void netsummoner_score(const unsigned score UNUSED) {
	struct network *net;

	net = arbiter(&aqueue);
	if(net && !connection && !wait_seconds) {
		printf("Network %s won!\n", net->name);
		switch(execute(net, EXEC_MATCH)) {
		case 0: //Execute went well
			connection = true;
			if(exit_on_connection) {
				module_netsummoner.timeout = 1;
			}
			break;
		case 1: //Exec with error
		case 3: //No assembly
			fprintf(stderr, "Disabling network %s\n", net->name);
			net->count = 0; //FIXME somehow properly free used memory
			net->target_score = 1;
			break;
		case 4:
			fprintf(stderr, "Execute already running\n");
			break;
		default:
			break;
		}
	} else if(!wait_seconds && !connection && abort_on_timeout)
		module_netsummoner.timeout = 1;
	bzero(&aqueue, sizeof(struct arbiter_queue)); //FIXME TRY TO DO PROPER CLEAN UP
	bzero(&ether_node_from, sizeof(struct stat_ether));
	bzero(&ether_node_to, sizeof(struct stat_ether));
	bzero(&ip_node_from, sizeof(struct stat_ip));
	bzero(&ip_node_to, sizeof(struct stat_ip));
	bzero(&wifi_node, sizeof(struct stat_wifi));
}

static void netsummoner_signal(void) {
	module_netsummoner.timeout = -1; //Wait for signal
}

static int netsummoner_callback(void *arg) {
	unsigned i;
	struct assembly *anode;

	if(arg == NETSUM_DELAYED) {
		wait_seconds = 0;
		module_netsummoner.arg = NETSUM_EXIT;
		module_netsummoner.timeout = -2; //Disabled
		netsummoner_score(0);
		return 0;
	} else {
		dhcpc_deinit();
		wifi_deinit();
		pcap_deinit();
		netlink_deinit();
		if(!exit_on_connection) {
			LIST_WALK(anode, &list_assembly) {
				for(i = 0; i < anode->count; i++) {
					if(anode->comb[i].active) {
						execute(anode->net, EXEC_DOWN);
					}
				}
			}
		}
		return 1; //Unregister
	} 
}

static void usage(void) {
	fprintf(stderr, "Usage: netsummoner OPTIONS\n\
-w <interface>	Enable WiFi scanning on <interface>\n\
-f <file>	Use dump file instead of live\n\
-i <interface>	Ethernet listening on <interface>\n\
-d  Send DHCP Offers\n\
-p  Promiscuous mode\n\
-v  Be verbose\n\
-c  Connect and exit\n\
-e <seconds> Wait <seconds> before choosing network\n\
-a  Abort when there is no connection after -e seconds\n\
-h  Show this help\
\n");
}

int main(int argc, char **argv) {
	int opt, ret;
	struct net_pcap np = { .score_fnc = netsummoner_score };
	char *wifidev = NULL;
	bool dhcp_active = 0;
	const char *interfaces[3] = {};
	
	while ((opt = getopt(argc, argv, "hvpw:f:i:dce:a")) >= 0) {
		switch(opt) {
		case 'w':
			wifidev = optarg;
			interfaces[1] = wifidev;
			break;
		case 'f':
			np.file = optarg;
			break;
		case 'i':
			np.dev = optarg;
			interfaces[0] = np.dev;
			break;
		case 'd':
			dhcp_active = 1;
			break;
		case 'p':
			np.promiscuous = 1;
			break;
		case 'v':
			show_received = 1;
			break;
		case 'c':
			exit_on_connection = 1;
			break;
		case 'e':
			wait_seconds = atoi(optarg);
			break;
		case 'a':
			abort_on_timeout = 1;
			break;
		case 'h':
		default:
			usage();
			return 1;
		}
	}

	list_init(&list_network);
	list_init(&list_action);
	list_init(&list_assembly);

	yyin = fopen("configure", "r");
	if(!yyin) {
		fprintf(stderr, "Unable to open configuration file\n");
		return 1;
	}
	ret = yyparse();
	if(ret != 0) {
		fprintf(stderr, "Errors in configuration file\n");
		return 1;
	}

	ret = netlink_init(interfaces);

	if(ret != 0) {
		fprintf(stderr, "Error in netlink module %d\n", ret);
		return 1;
	}

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
		ret = wifi_init(wifidev, netsummoner_score);
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

	if(wait_seconds) {
		module_netsummoner.arg = NETSUM_DELAYED;
		module_netsummoner.timeout = wait_seconds * 1000;
	} else {
		module_netsummoner.arg = NETSUM_EXIT;
		module_netsummoner.timeout = -2; //Disabled
	}
	module_netsummoner.fnc = (dispatch_callback) netsummoner_callback;
	module_netsummoner.fd = -1;  //Not used
	signal_callback = netsummoner_signal;

	if(register_module(&module_netsummoner, "Netsummoner")) {
		fprintf(stderr, "Unable to register netsummoner module\n");
		return 1;
	}

	execute_close_on_connect(exit_on_connection);
	daemonize();
	(void) dispatch_loop();
	printf("Main loop ended\n");
	return 0;
}

