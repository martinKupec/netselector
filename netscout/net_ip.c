#include <stdint.h>
#include <stdio.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>

#include "netscout.h"
#include "network.h"

typedef unsigned char byte;
#define IPQUAD(x) ((byte*)&(x))[0], ((byte*)&(x))[1], ((byte*)&(x))[2], ((byte*)&(x))[3]

#define UDP_PORT_NBNS	137
#define UDP_PORT_DHCP	67
#define UDP_PORT_SSDP	1900

void printf_nbname(const unsigned char *name) {
	int i;

	for(i = 0; i < 16; i++) {
		putchar(((name[2*i] - 'A') << 4) + (name[2*i + 1] - 'A'));
	}
	putchar(' ');
}

void net_nbns(const uint8_t *pkt) {
	//printf_nbname(pkt + 13);
	return;
}

void net_hndl_udp(const uint8_t *pkt) {
	const struct udphdr *hdr = (const struct udphdr *) pkt;
	uint16_t dport = ntohs(hdr->dest);

	switch(dport) {
	case UDP_PORT_NBNS: //WinVista uses lmnr but probably duplicate to NBNS
		net_nbns(pkt + sizeof(struct udphdr));
	case UDP_PORT_DHCP:
		break;
	case UDP_PORT_SSDP:
		break;
	default:
		printf("UDP SPort:%d DPort:%d\n", ntohs(hdr->source), ntohs(hdr->dest));
		break;
	}
	return;
}

void net_hndl_ip(const uint8_t *pkt) {
	const struct iphdr *hdr = (const struct iphdr *) pkt;

	//printf("From:%03d.%03d.%03d.%03d To:%03d.%03d.%03d.%03d\n", IPQUAD(hdr->saddr), IPQUAD(hdr->daddr));
	switch(hdr->protocol) {
	case IPPROTO_TCP:
		//printf("Prot: TCP\n");
		break;
	case IPPROTO_UDP:
		net_hndl_udp(pkt + (hdr->ihl * 4));
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

