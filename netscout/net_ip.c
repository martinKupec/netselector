#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>

#include "netscout.h"
#include "network.h"
#include "list.h"
#include "dhcpc.h"

typedef unsigned char byte;
#define IPQUAD(x) ((byte*)&(x))[0], ((byte*)&(x))[1], ((byte*)&(x))[2], ((byte*)&(x))[3]

#define UDP_PORT_NBNS	137
#define UDP_PORT_DHCPS	68
#define UDP_PORT_DHCPC	67
#define UDP_PORT_SSDP	1900

void sprint_nbname(char *buf, const unsigned char *name) {
	int i;

	for(i = 0; i < 16; i++) {
		buf[i] = ((name[2*i] - 'A') << 4) + (name[2*i + 1] - 'A');
	}
}

void net_nbns(const uint8_t *pkt, shell *sh) {
	struct stat_nbname *node;
	char buf[16];
	unsigned int here;

	sprint_nbname(buf, pkt + 13);

	node = list_nbname_add_uniq(buf);
	if(node->ip == NULL) {
		node->ip = (struct stat_ip **) malloc(sizeof(struct stat_ip *) * 16);
		node->time = (uint32_t *) malloc(sizeof(uint32_t) * 16);
	} else {
		if((node->ip_count & 0x0F) == 0x0F) {
			node->ip = (struct stat_ip **) realloc(node->ip, sizeof(struct stat_ip *) * (node->ip_count + 16));
			node->time = (uint32_t *) realloc(node->time, sizeof(uint32_t) * (node->ip_count + 16));
		}
	}
	if(!node->ip_count) {
		here = 0;
	} else if(sh->lower_from == node->ip[node->ip_count - 1]) {
		here = node->ip_count;
	} else {
		for(here = 0; here < node->ip_count; here++) {
			if(sh->lower_from == node->ip[here]) {
				break;
			}
		}
		for(; here < node->ip_count; here++) {
			if(sh->lower_from != node->ip[here]) {
				bcopy(node->ip + here, node->ip + here + 1, sizeof(struct stat_ip *) * (node->ip_count - here));
				break;
			}
		}
	}
	node->ip[here] = sh->lower_from;
	node->time[here] = sh->time;
	node->ip_count++;
	return;
}

void net_hndl_udp(const uint8_t *pkt, shell *sh) {
	const struct udphdr *hdr = (const struct udphdr *) pkt;
	uint16_t dport = ntohs(hdr->dest);

	switch(dport) {
	case UDP_PORT_NBNS: //WinVista uses lmnr but probably duplicate to NBNS
		net_nbns(pkt + sizeof(struct udphdr), sh);
		break;
	case UDP_PORT_DHCPC:
		printf("DHCP CLIENT\n");
		break;
	case UDP_PORT_DHCPS:
		dhcpc_packet(pkt, sh);
		break;
	case UDP_PORT_SSDP:
		printf("SSDP\n");
		break;
	default:
		printf("UDP SPort:%d DPort:%d\n", ntohs(hdr->source), ntohs(hdr->dest));
		break;
	}
	return;
}

static inline void use_possibly_new_node(struct stat_ip *node, struct stat_ether *eth, uint32_t time) {
	if(node->ether == NULL) {
		node->ether = (struct stat_ether **) malloc(sizeof(struct stat_ether *) * 16);
		node->time = (uint32_t *) malloc(sizeof(uint32_t) * 16);
	} else {
		if((node->ether_count & 0x0F) == 0x0F) {
			node->ether = (struct stat_ether **) realloc(node->ether, sizeof(struct stat_ether *) * (node->ether_count + 16));
			node->time = (uint32_t *) realloc(node->time, sizeof(uint32_t) * (node->ether_count + 16));
		}
	}
	node->ether[node->ether_count] = eth;
	node->time[node->ether_count++] = time;
}

void net_hndl_ip(const uint8_t *pkt, shell *sh) {
	const struct iphdr *hdr = (const struct iphdr *) pkt;
	struct stat_ip *node = list_ip_add_uniq(hdr->daddr);

	use_possibly_new_node(node, sh->lower_to, sh->time);
	sh->lower_to = node;

	node = list_ip_add_uniq(hdr->saddr);

	use_possibly_new_node(node, sh->lower_from, sh->time);
	sh->lower_from = node;

	//printf("From:%03d.%03d.%03d.%03d To:%03d.%03d.%03d.%03d\n", IPQUAD(hdr->saddr), IPQUAD(hdr->daddr));
	switch(hdr->protocol) {
	case IPPROTO_TCP:
		//printf("Prot: TCP\n");
		break;
	case IPPROTO_UDP:
		net_hndl_udp(pkt + (hdr->ihl * 4), sh);
		break;
	case IPPROTO_ICMP:
		printf("ICMP\n");
		break;
	default:
		printf("Prot: %d\n", hdr->protocol);
		break;
	}
	return;
}

