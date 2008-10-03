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

/*
 * Dispatcher for UDP packets
 */
void net_hndl_udp(const uint8_t *pkt, shell *sh) {
	const struct udphdr *hdr = (const struct udphdr *) pkt;
	const uint16_t dport = ntohs(hdr->dest);

	switch(dport) {
	case UDP_PORT_NBNS: //WinVista uses lmnr but probably duplicate to NBNS
		net_hndl_nbns(pkt + sizeof(struct udphdr), sh);
		break;
	case UDP_PORT_DHCPC:
		sh->from.higher_type = IP_TYPE_DHCPC;
		sh->from.higher_data = NULL;
		sh->to.higher_type = IP_TYPE_NONE;
		sh->to.higher_data = NULL;
		break;
	case UDP_PORT_DHCPS:
		dhcpc_packet(pkt + sizeof(struct udphdr), sh);
		break;
	case UDP_PORT_SSDP:
		sh->from.higher_type = IP_TYPE_SSDP;
		sh->from.higher_data = NULL;
		sh->to.higher_type = IP_TYPE_NONE;
		sh->to.higher_data = NULL;
		break;
	default:
		sh->from.higher_type = IP_TYPE_UDP;
		sh->from.higher_data = (void *) ((ntohs(hdr->source) << 16) | (ntohs(hdr->dest)));
		sh->to.higher_type = IP_TYPE_NONE;
		sh->to.higher_data = NULL;
		break;
	}
}

/*
 * Basic handler for IP packets
 */
void net_hndl_ip(const uint8_t *pkt, shell *sh) {
	const struct iphdr *hdr = (const struct iphdr *) pkt;
	void *lower_from = sh->from.lower_node, *lower_to = sh->to.lower_node;

	sh->to.lower_node = list_ip_add_uniq(hdr->daddr);
	sh->from.lower_node = list_ip_add_uniq(hdr->saddr);

	switch(hdr->protocol) {
	case IPPROTO_TCP:
		sh->from.higher_type = IP_TYPE_TCP;
		sh->from.higher_data = NULL;
		sh->to.higher_type = IP_TYPE_NONE;
		sh->to.higher_data = NULL;
		break;
	case IPPROTO_UDP:
		net_hndl_udp(pkt + (hdr->ihl * 4), sh);
		break;
	case IPPROTO_ICMP:
		sh->from.higher_type = IP_TYPE_ICMP;
		sh->from.higher_data = NULL;
		sh->to.higher_type = IP_TYPE_NONE;
		sh->to.higher_data = NULL;
		break;
	default:
		sh->from.higher_type = IP_TYPE_UNKNOWN;
		sh->from.higher_data = (void *) ((uint32_t) hdr->protocol);
		sh->to.higher_type = IP_TYPE_NONE;
		sh->to.higher_data = NULL;
		break;
	}

	ip_node_set_info(&sh->from, sh->time);
	ip_node_set_info(&sh->to, sh->time);

	sh->from.lower_node = lower_from;
	sh->from.higher_type = ETH_TYPE_IP;
	sh->from.higher_data = sh->from.lower_node;
	sh->to.lower_node = lower_to;
	sh->to.higher_type = ETH_TYPE_IP;
	sh->to.higher_data = sh->to.lower_node;
}

