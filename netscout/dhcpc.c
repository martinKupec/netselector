
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "netscout.h"
#include "dhcpc.h"
#include "list.h"

#define DHCPOFFER	2

#define DHCP_OPTIONS_SIZE 308 /* 312 - cookie */
struct dhcp_packet {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t cookie;
	uint8_t options[DHCP_OPTIONS_SIZE]; 
};

struct whole_packet {
	struct ether_header eth;
	struct iphdr ip;
	struct udphdr udp;
	struct dhcp_packet dhcp;
} PACKED;

static struct whole_packet wpkt;

/* Stole from udhcp */
uint16_t checksum(void *addr, int count)
{
	/* Compute Internet Checksum for "count" bytes
	 *         beginning at location "addr".
	 */
	register int32_t sum = 0;
	uint16_t *source = (uint16_t *) addr;

	while (count > 1)  {
		/*  This is the inner loop */
		sum += *source++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if (count > 0) {
		/* Make sure that the left-over byte is added correctly both
		 * with little and big endian hosts */
		uint16_t tmp = 0;
		*(uint8_t *) (&tmp) = *(uint8_t *) source;
		sum += tmp;
	}
	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

#define BOOTREQUEST 1

int dhcp_option_add(uint8_t *opt_field, uint8_t opt_type, uint8_t len, uint8_t *data) {
	int i;

	if(len == 0) {
		opt_field[0] = opt_type;
		return 1;
	} else {
		opt_field[0] = opt_type;
		opt_field[1] = len;
		for(i = 0; i < len; i++) {
			opt_field[2 + i] = *data++;
		}
		return len + 2;
	}
}

void packet_fill_offer(struct dhcp_packet *pkt, uint32_t xid, char *hwaddr) {
	int opt_ptr;
	uint8_t type;
	const char vendor_id[] = "NetScout";

	pkt->op = BOOTREQUEST;
	pkt->htype = 1;
	pkt->hlen = 6;
	pkt->hops = 0;
	pkt->xid = xid;
	pkt->secs = 0;
	pkt->flags = htons(0x8000); //broadcast
	pkt->ciaddr = 0;
	pkt->yiaddr = 0;
	pkt->siaddr = 0;
	pkt->giaddr = 0;
	memcpy(pkt->chaddr, hwaddr, 6);
	pkt->cookie = htonl(0x63825363);

	type = DHCP_TYPE_DISCOVER;
	opt_ptr = dhcp_option_add(pkt->options, DHCP_TYPE_MESSAGE, 1, &type);
	opt_ptr += dhcp_option_add(pkt->options + opt_ptr, DHCP_TYPE_VENDOR_ID, sizeof(vendor_id),(uint8_t *) vendor_id);

	dhcp_option_add(pkt->options + opt_ptr, 0xFF, 0, NULL);
}

void packet_finalize(struct whole_packet *pkt, char *hwaddr, uint16_t ipid) {
	memset(pkt->eth.ether_dhost, 0xFF, 6);
	memcpy(pkt->eth.ether_shost, hwaddr, 6);
	pkt->eth.ether_type = htons(ETHERTYPE_IP);

	pkt->ip.protocol = IPPROTO_UDP;
	pkt->ip.saddr = 0;
	pkt->ip.daddr = 0xFFFFFFFF;
	pkt->ip.tot_len = htons(sizeof(struct udphdr) + sizeof(struct dhcp_packet)); //cheat - UDP pseudo-header length
	pkt->udp.source = htons(68); //bootpc
	pkt->udp.dest = htons(67); //bootps
	pkt->udp.len = pkt->ip.tot_len;
	pkt->udp.check = checksum(&pkt->ip, sizeof(struct whole_packet) - sizeof(struct ether_header));
		//small cheat, checksum whole ip header instead of pseudo-one, but with all zeros - except pseudo-one

	pkt->ip.ihl = sizeof(struct iphdr) >> 2;
	pkt->ip.version = IPVERSION;
	pkt->ip.tos = IPTOS_TOS(IPTOS_LOWCOST);
	pkt->ip.tot_len = htons(sizeof(struct whole_packet) - sizeof(struct ether_header));
	pkt->ip.id = htons(ipid);
	pkt->ip.frag_off = htons(IP_DF);
	pkt->ip.ttl = IPDEFTTL;
	pkt->ip.check = checksum(&pkt->ip, sizeof(struct iphdr));
}

void dhcpc_offers(pcap_t *hndl, char *interface) {
	struct ifreq ifr;
	int ret, fd;
	uint32_t rid;

	if(wpkt.eth.ether_type == 0) {
		fd = open("/dev/urandom", 0);
		read(fd, &rid, sizeof(uint32_t));

        strcpy(ifr.ifr_name, interface);
		if(ioctl(*((int *) hndl), SIOCGIFHWADDR, &ifr) < 0) {
			fprintf(stderr, "HW address unresolvable error:%s\n", strerror(errno));
			return;
		}

		packet_fill_offer(&wpkt.dhcp, rid, ifr.ifr_hwaddr.sa_data);
		packet_finalize(&wpkt, ifr.ifr_hwaddr.sa_data, (uint16_t) rid);
		ret = pcap_sendpacket(hndl, (uint8_t *) &wpkt, sizeof(struct whole_packet));
		if(ret) {
			fprintf(stderr, "Unable to send DHCP Discover\n");
		}
	} else {

	}
}

void dhcpc_packet(const uint8_t *pkt, shell *sh) {
	int i;
	int offer = 0;
	struct stat_dhcp *node;
	uint8_t mask[4], router[4], dns[2][4], server[4];
	struct dhcp_packet *dpkt = (struct dhcp_packet *) pkt;
	const uint8_t *options = dpkt->options;

	bzero(mask, 4);
	bzero(router, 4);
	bzero(server, 4);
	bzero(dns, 8);

	for(i = 0; options[i] != 255;) {
		switch(options[i]) {
		case 0: //Padding
			i++;
			continue; //Special size
		case 1: //Subnet mask
			memcpy(mask, options + i + 2, 4);
			break;
		case 3://Router
			memcpy(router, options + i + 2, 4);
			break;
		case 6:// Domain Name Server
			memcpy(&dns[0][0], options + i + 2, 4);
			memcpy(&dns[1][0], options + i + 2 + 4, 4);
			break;
		case 17: //Domain Name
			break;
		case 53: //DHCP Type
			if(options[i + 2] == DHCPOFFER) {
				offer = 1;
			}
			break;
		case 54: //DHCP Server Identifier
			memcpy(server, options + i + 2, 4);
			break;
		default:
			break;
		}
		i += options[i + 1] + 2;
	}
	if(offer) {
		node = list_dhcp_add_uniq(server);
		memcpy(node->router_IP, router, 4);
		memcpy(node->dnsp, dns[0], 4);
		memcpy(node->dnss, dns[1], 4);
		memcpy(node->mask, router, 4);
		node->ip = sh->lower_from;
		node->time = sh->time;
	}
}
