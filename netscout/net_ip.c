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
#include "link.h"
#include "dhcpc.h"

#define UDP_PORT_NBNS	137
#define UDP_PORT_DHCPS	68
#define UDP_PORT_DHCPC	67
#define UDP_PORT_SSDP	1900
#define UDP_PORT_DNS	53

/*
 * Dispatcher for UDP packets
 */
static unsigned net_hndl_udp(const uint8_t *pkt, shell *sh) {
	const struct udphdr *hdr = (const struct udphdr *) pkt;
	const uint16_t dport = ntohs(hdr->dest);
	unsigned score;

	switch(dport) {
	case UDP_PORT_NBNS: //WinVista uses lmnr but probably duplicate to NBNS
		score = net_hndl_nbns(pkt + sizeof(struct udphdr), sh);
		break;
	case UDP_PORT_DHCPC:
		sh->from.higher_type = IP_TYPE_DHCPC;
		sh->from.higher_data = NULL;
		sh->to.higher_type = IP_TYPE_NONE;
		sh->to.higher_data = NULL;
		score = SCORE_DHCPC;
		break;
	case UDP_PORT_DHCPS:
		dhcpc_packet(pkt + sizeof(struct udphdr), sh);
		score = SCORE_DHCPS;
		break;
	case UDP_PORT_SSDP:
		sh->from.higher_type = IP_TYPE_SSDP;
		sh->from.higher_data = NULL;
		sh->to.higher_type = IP_TYPE_NONE;
		sh->to.higher_data = NULL;
		score = SCORE_SSDP;
		break;
	default:
		sh->from.higher_type = IP_TYPE_UDP;
		sh->from.higher_data = (void *) ((ntohs(hdr->source) << 16) | (ntohs(hdr->dest)));
		sh->to.higher_type = IP_TYPE_NONE;
		sh->to.higher_data = NULL;
		score = SCORE_UDP_UNKNOWN;
		break;
	}
	return score;
}

/*
 * Basic handler for IP packets
 */
unsigned net_hndl_ip(const uint8_t *pkt, shell *sh) {
	const struct iphdr *hdr = (const struct iphdr *) pkt;
	void *lower_from = sh->from.lower_node, *lower_to = sh->to.lower_node;
	unsigned score = SCORE_IP;

	sh->to.lower_node = list_ip_add_uniq(hdr->daddr);
	((struct stat_ip *)(sh->to.lower_node))->ether = lower_to;
	sh->from.lower_node = list_ip_add_uniq(hdr->saddr);
	((struct stat_ip *)(sh->from.lower_node))->ether = lower_from;

	switch(hdr->protocol) {
	case IPPROTO_TCP:
		sh->from.higher_type = IP_TYPE_TCP;
		sh->from.higher_data = NULL;
		sh->to.higher_type = IP_TYPE_NONE;
		sh->to.higher_data = NULL;
		score += SCORE_TCP;
		break;
	case IPPROTO_UDP:
		score += net_hndl_udp(pkt + (hdr->ihl * 4), sh);
		break;
	case IPPROTO_ICMP:
		sh->from.higher_type = IP_TYPE_ICMP;
		sh->from.higher_data = NULL;
		sh->to.higher_type = IP_TYPE_NONE;
		sh->to.higher_data = NULL;
		score += SCORE_ICMP;
		break;
	default:
		sh->from.higher_type = IP_TYPE_UNKNOWN;
		sh->from.higher_data = (void *) ((uint32_t) hdr->protocol);
		sh->to.higher_type = IP_TYPE_NONE;
		sh->to.higher_data = NULL;
		score += SCORE_IP_UNKNOWN;
		break;
	}

	ip_node_set_info(&sh->from, sh->time);
	ip_node_set_info(&sh->to, sh->time);

	sh->from.higher_type = ETH_TYPE_IP;
	sh->from.higher_data = sh->from.lower_node;
	sh->from.lower_node = lower_from;
	sh->to.higher_type = ETH_TYPE_IP;
	sh->to.higher_data = sh->to.lower_node;
	sh->to.lower_node = lower_to;
	return score;
}

