#include <stdio.h>
#include <stdarg.h>

#include "netscout.h"
#include "statistics.h"
#include "list.h"
#include "score.h"

#define SPACE_FIRST		40
#define SPACE_SECOND	80

struct pseudo_node {
	unsigned count;
	struct info_field *info;
};

static unsigned on_eth(const uint8_t *mac, unsigned space) {
	if(show_received) {
		while(space < SPACE_FIRST) {
			space++;
			putchar(' ');
		}
		return printf("on ETH %02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2],
				mac[3], mac[4], mac[5]);
	} else {
		return 0;
	}
}

static void verdict(unsigned space, const char *format, ...) {
	va_list va;
	
	if(!show_received) {
		return;
	}
	while(space < (SPACE_SECOND - SPACE_FIRST)) {
		space++;
		putchar(' ');
	}
	va_start(va, format);
	vprintf(format, va);
	va_end(va);
}

static unsigned is_router(const struct info_field *info, unsigned pos, const unsigned size, const unsigned space) {
	unsigned num = 0;

	while(pos) {
		pos--;
		if(info[pos].type == ETH_TYPE_IP) {
			num++;
		} else {
			pos++;
			break;
		}
	}
	pos += num + 1;
	while(pos < size) {
		if(info[pos].type == ETH_TYPE_IP) {
			num++;
			pos++;
		} else {
			break;
		}
	}
	if(num) {
		verdict(space, "Probable Gateway (%d)", num + 1);
		if(num > 4) {
			return SCORE_GATEWAY;
		}
	}
	return 0;
}

/*
 * Returns score and prints info about new information 
 */
static unsigned info_data_score(const void *node, const struct info_field *info, bool show) {
	unsigned space = 0;
	const struct stat_ether *neth = (struct stat_ether *)(node);
	const struct stat_ip *nip = (struct stat_ip *)(node);

	switch(info->type) {
	case ETH_TYPE_IP:
		if(show_received) {
			space = printf("IP %d.%d.%d.%d", IPQUAD(((const struct stat_ip *)info->data)->ip));
		}
		space = on_eth(neth->mac, space);
		space = is_router(neth->info, info - neth->info, neth->count, space);
		if(show_received) {
			putchar('\n');
		}
		return space; // IP Added when adding to list, adding just score for gateway
	case ETH_TYPE_CDP:
		space = statistics_cdp(info, 1);
		space = on_eth(neth->mac, space);
		verdict(space, "Router\n");
		return SCORE_CDP;
	case ETH_TYPE_STP:
		space = statistics_stp(info, 1);
		space = on_eth(neth->mac, space);
		verdict(space, "Router\n");
		return SCORE_STP;
	case IP_TYPE_NBNS:
		return SCORE_NBNS;
	case IP_TYPE_DHCPS:
		space = statistics_dhcps(info, 1);
		space = on_eth(nip->ether->mac, space);
		verdict(space, "DHCP Server\n");
		return SCORE_DHCPS;
	case IP_TYPE_ARP:
		return SCORE_ARP;
	case IP_TYPE_DNSS:
		if(show_received) {
			space = printf("DNS %d.%d.%d.%d", IPQUAD(nip->ip));
		}
		space = on_eth(nip->ether->mac, space);
		verdict(space, "DNS Server\n");
		return SCORE_DNSS;
	case IP_TYPE_DNSC:
		return SCORE_DNSC;
	case ETH_TYPE_STP_UNKNOWN:
	case ETH_TYPE_CDP_UNKNOWN:
	case ETH_TYPE_SNAP_UNKNOWN:
	case ETH_TYPE_ARP_UNKNOWN:
	case ETH_TYPE_LLC_UNKNOWN:
	case ETH_TYPE_UNKNOWN:
	case IP_TYPE_UNKNOWN:
		return SCORE_UNKNOWN;
	case ETH_TYPE_WLCCP:
		if(show_received) {
			space = printf("WLCCP");
		}
		space = on_eth(neth->mac, space);
		verdict(space, "Cisco Router\n");
		return SCORE_WLCCP;
	case ETH_TYPE_EAP:
		if(show_received) {
			space = printf("EAP");
		}
		space = on_eth(neth->mac, space);
		verdict(space, "EAP Server\n");
		return SCORE_EAP;
	case ETH_TYPE_REVARP:
		return SCORE_REVARP;
	case ETH_TYPE_VLAN:
		return SCORE_VLAN;
	case IP_TYPE_ICMP:
		return SCORE_ICMP;
	case IP_TYPE_TCP:
		return SCORE_TCP;
	case IP_TYPE_UDP:
		return SCORE_UDP;
	case IP_TYPE_SSDP:
		return SCORE_SSDP;
	case IP_TYPE_DHCPC:
		return SCORE_DHCPC;
	default:
		return 0;
	}
}

/*
 * Returns size of data for given type
 */
static size_t info_data_size(const uint32_t type) {
	switch(type) {
	case ETH_TYPE_IP:
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
	case IP_TYPE_ARP:
	case IP_TYPE_TCP:
	case IP_TYPE_UDP:
	case IP_TYPE_SSDP:
	case IP_TYPE_DHCPC:
	case IP_TYPE_UNKNOWN:
	default:
		return 0;
	}
}

/*
 * Compare to info fields
 */
static int info_cmp(const struct info_field *info, unsigned type, void *data, size_t size) {
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

/*
 * Finds nearest info in info field, and indicate if it is match or not
 */
static unsigned node_info_find(const struct info_field *info, const unsigned count, const struct shell_exchange *ex, int *found) {
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
unsigned node_set_info(const struct shell_exchange *ex, const uint32_t time, const int node_type) {
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
				info_data_size(ex->higher_type)) {
			free(ex->higher_data);
		}
		return 0;
	}
	node->info[here].type = ex->higher_type;
	node->info[here].data = ex->higher_data;
	node->info[here].time_first = time;
	node->info[here].time_last = time;
	node->info[here].count++;

	return info_data_score(whole_node, node->info + here, 1);
}
