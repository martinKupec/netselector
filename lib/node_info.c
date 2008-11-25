#include <stdio.h>
#include <stdarg.h>

#include "lib/netselector.h"
#include "lib/node_info.h"
#include "lib/list.h"
#include "lib/score.h"

#define SHOW_TIME(time) time / 1000, time % 1000

#define SPACE_SIZE	60
#define SPACE_FIRST	40
#define SPACE_SECOND 80

struct pseudo_node {
	unsigned count;
	struct info_field *info;
};

static int cond_printf(const char *fmt, ...) {
	va_list va;
	int ret;

	if(!show_received) {
		return 0;
	}
	va_start(va, fmt);
	ret = vprintf(fmt, va);
	va_end(va);
	return ret;
}

void show_time(const struct info_field *info, unsigned space) {

	if(!show_received) {
		return;
	}
	while(space < SPACE_SIZE) {
		putchar(' ');
		space++;
	}
	cond_printf("First %03u.%03u ", SHOW_TIME(info->time_first));
	cond_printf("Last %03u.%03u ", SHOW_TIME(info->time_last));
	cond_printf("Count %d\n", info->count);
}

void show_nbns(const struct info_field *info) {
	const struct proto_nbname *nbname = info->data;
	char buf[17];
	unsigned space;

	memcpy(buf, nbname->name, 16);
	buf[16] = '\0';
	space = cond_printf("        Ask's NBName %s", buf);
	show_time(info, space);
}

unsigned show_dhcps(const struct info_field *info, bool oneline) {
	const struct proto_dhcp *dhcp = info->data;
	unsigned space;

	if(!oneline) {
		cond_printf("        ");
	}
	space = cond_printf("DHCP %d.%d.%d.%d", IPQUAD(dhcp->server_IP));
	if(oneline) {
		return space;
	} else {
		show_time(info, space + 8);
		cond_printf("            Router %d.%d.%d.%d\n", IPQUAD(dhcp->router_IP));
		cond_printf("            DNS %d.%d.%d.%d %d.%d.%d.%d\n", IPQUAD(dhcp->dnsp), IPQUAD(dhcp->dnss));
		cond_printf("            Mask %d.%d.%d.%d\n", IPQUAD(dhcp->mask));
		return 0;
	}
}

unsigned show_stp(const struct info_field *info, bool oneline) {
	const struct proto_stp *stp = info->data;
	unsigned space;

	if(!oneline) {

		space = cond_printf("    STP Bridge: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", stp->bridge[0],
				stp->bridge[1], stp->bridge[2], stp->bridge[3], stp->bridge[4],
				stp->bridge[5], stp->bridge[6], stp->bridge[7]);
		show_time(info, space);
		cond_printf("        ");
	}
	space = cond_printf("Root: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", stp->root[0],
		stp->root[1], stp->root[2], stp->root[3], stp->root[4], stp->root[5],
		stp->root[6], stp->root[7]);
	if(!oneline) {
		cond_printf("\n        Port: %04X\n", stp->port);
		return 0;
	} else {
		return space + cond_printf(" Port:%04X", stp->port);
	}
}

unsigned show_cdp(const struct info_field *info, bool oneline) {
	const struct proto_cdp *cdp = info->data;
	unsigned space = 0;

	if(oneline) {
		return cond_printf("CDP %s Port %s", cdp->did, cdp->port);
	} else {
		space = cond_printf("    CDP Device ID %s ", cdp->did);
		show_time(info, space);
		cond_printf("        Port %s\n        Version %s\n        Platform %s\n", cdp->port, cdp->ver, cdp->plat);;
	}
	return 0;
}

static unsigned on_eth(const uint8_t *mac, unsigned space) {

	if(!show_received) {
		return 0;
	}
	while(space < SPACE_FIRST) {
		space++;
		putchar(' ');
	}
	return cond_printf("on ETH %02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);
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
static unsigned info_data_score(const void *node, const struct info_field *info) {
	unsigned space = 0;
	const struct stat_ether *neth = (struct stat_ether *)(node);
	const struct stat_ip *nip = (struct stat_ip *)(node);

	switch(info->type) {
	case ETH_TYPE_IP:
		space = cond_printf("IP %d.%d.%d.%d", IPQUAD(((const struct stat_ip *)info->data)->ip));
		space = on_eth(neth->mac, space);
		space = is_router(neth->info, info - neth->info, neth->count, space);
		cond_printf("\n");
		return space; // IP Added when adding to list, adding just score for gateway
	case ETH_TYPE_CDP:
		space = show_cdp(info, 1);
		space = on_eth(neth->mac, space);
		verdict(space, "Router\n");
		return SCORE_CDP;
	case ETH_TYPE_STP:
		space = show_stp(info, 1);
		space = on_eth(neth->mac, space);
		verdict(space, "Router\n");
		return SCORE_STP;
	case IP_TYPE_NBNS:
		return SCORE_NBNS;
	case IP_TYPE_DHCPS:
		space = show_dhcps(info, 1);
		space = on_eth(nip->ether->mac, space);
		verdict(space, "DHCP Server\n");
		return SCORE_DHCPS;
	case IP_TYPE_ARP:
		return SCORE_ARP;
	case IP_TYPE_DNSS:
		space = cond_printf("DNS %d.%d.%d.%d", IPQUAD(nip->ip));
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
		space = cond_printf("WLCCP");
		space = on_eth(neth->mac, space);
		verdict(space, "Cisco Router\n");
		return SCORE_WLCCP;
	case ETH_TYPE_EAP:
		space = cond_printf("EAP");
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
	case WIFI_TYPE_QUALITY:
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
	unsigned i = 0, j = count - 1, a;
	int c = 1;

	if(!count) {
		return 0;
	}
	while(c && (i <= j)) {
		a = (i + j) / 2;
		c = info_cmp(info + a, ex->higher_type, ex->higher_data, size);
		if(c < 0) {
			i = a + 1;
		} else if(c > 0) {
			if(!a) {
				return 0;
			} 
			j = a - 1;
		} 
	}
	if(!c) { //Exact match
		if(found) {
			*found = 1;
		}
		return a;
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
	case NODE_TYPE_WIFI:
		node = (struct pseudo_node *) &(((struct stat_wifi *)(whole_node))->count);
		break;
	default:
		node = NULL;
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

	return info_data_score(whole_node, node->info + here);
}
