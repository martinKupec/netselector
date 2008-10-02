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

static int sent_offer;

/* Stole from udhcp */
/* Compute Internet Checksum for "count" bytes
 *         beginning at location "addr".
 */
static uint16_t checksum(const void *addr, int count) {
	register int32_t sum = 0;
	const uint16_t *source = (const uint16_t *) addr;

	while (count > 1) {
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
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

/*
 * Adds option to option field and return how long it was
 */
static int dhcp_option_add(uint8_t *opt_field, uint8_t opt_type, uint8_t len, uint8_t *data) {
	if(len == 0) {
		opt_field[0] = opt_type;
		return 1;
	} else {
		int i;

		opt_field[0] = opt_type;
		opt_field[1] = len;
		for(i = 0; i < len; i++) {
			opt_field[2 + i] = *data++;
		}
		return len + 2;
	}
}
/*
 * Fills packets DHCP part
 */
static void packet_fill_offer(struct dhcp_packet *pkt, const uint32_t xid, const uint8_t *hwaddr) {
	int opt_ptr;
	uint8_t type;
	const char vendor_id[] = "NetScout";

	pkt->op = BOOTPREQUEST;
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
	pkt->cookie = htonl(0x63825363); //Magic Cookie

	type = DHCP_DISCOVER;
	opt_ptr = dhcp_option_add(pkt->options, DHCP_TYPE_MESSAGE, 1, &type);
	opt_ptr += dhcp_option_add(pkt->options + opt_ptr, DHCP_TYPE_VENDOR_ID, sizeof(vendor_id),(uint8_t *) vendor_id);

	dhcp_option_add(pkt->options + opt_ptr, DHCP_TYPE_END, 0, NULL); //End
}

/*
 * Adds headers to packet
 */
static void packet_finalize(struct whole_packet *pkt, const uint8_t *hwaddr, const uint16_t xid) {
	memset(pkt->eth.ether_dhost, 0xFF, 6);
	memcpy(pkt->eth.ether_shost, hwaddr, 6);
	pkt->eth.ether_type = htons(ETHERTYPE_IP);

	pkt->ip.protocol = IPPROTO_UDP;
	pkt->ip.saddr = 0; //From noone
	pkt->ip.daddr = 0xFFFFFFFF; //To everyone
	pkt->ip.tot_len = htons(sizeof(struct udphdr) + sizeof(struct dhcp_packet)); //cheat - UDP pseudo-header length
	pkt->udp.source = htons(BOOTPC_PORT);
	pkt->udp.dest = htons(BOOTPS_PORT);
	pkt->udp.len = pkt->ip.tot_len;
	pkt->udp.check = checksum(&pkt->ip, sizeof(struct whole_packet) - sizeof(struct ether_header));
		//small cheat, checksum whole ip header instead of pseudo-one, but with all zeros - except pseudo-one

	pkt->ip.ihl = sizeof(struct iphdr) >> 2; //Ip header size in quads
	pkt->ip.version = IPVERSION;
	pkt->ip.tos = IPTOS_TOS(IPTOS_LOWCOST);
	pkt->ip.tot_len = htons(sizeof(struct whole_packet) - sizeof(struct ether_header));
	pkt->ip.id = htons(xid);
	pkt->ip.frag_off = htons(IP_DF);
	pkt->ip.ttl = IPDEFTTL;
	pkt->ip.check = checksum(&pkt->ip, sizeof(struct iphdr));
}

/*
 * Sends DHCP discovver, once in 254 calls, stops when received offer
 */
void dhcpc_offers(pcap_t *hndl, const char *interface) {
	if(!sent_offer) {
		int fd;
		uint32_t rid;
		struct ifreq ifr;
		struct whole_packet wpkt;

		fd = open("/dev/urandom", 0);
		read(fd, &rid, sizeof(uint32_t));
		close(fd);

		//Get HW addr
        strcpy(ifr.ifr_name, interface);
		if(ioctl(*((int *) hndl), SIOCGIFHWADDR, &ifr) < 0) {
			fprintf(stderr, "HW address unresolvable error:%s\n", strerror(errno));
			return;
		}

		packet_fill_offer(&wpkt.dhcp, rid, (uint8_t *) ifr.ifr_hwaddr.sa_data);
		packet_finalize(&wpkt, (uint8_t *) ifr.ifr_hwaddr.sa_data, (uint16_t) rid);
		if(pcap_sendpacket(hndl, (uint8_t *) &wpkt, sizeof(struct whole_packet)) ) {
			fprintf(stderr, "Unable to send DHCP Discover\n");
		}
		sent_offer = 254;
	} else {
		if(sent_offer != 255) {
			sent_offer--;
		}
	}
}

/*
 * Handles received packets
 */
void dhcpc_packet(const uint8_t *pkt, shell *sh) {
	int i;
	struct proto_dhcp *info;
	uint32_t mask = 0, router = 0, dns[2] = {0, 0}, server = 0;
	const struct dhcp_packet *dpkt = (const struct dhcp_packet *) pkt;
	const uint8_t *options = dpkt->options;

	for(i = 0; options[i] != 255;) {
		switch(options[i]) {
		case DHCP_TYPE_PAD:
			i++;
			continue; //Special size
		case DHCP_TYPE_MASK:
			mask = *((uint32_t *)(options + i + 2));
			break;
		case DHCP_TYPE_ROUTER:
			router = *((uint32_t *)(options + i + 2));
			break;
		case DHCP_TYPE_DNS:
			dns[0] = *((uint32_t *)(options + i + 2));
			if(options[i + 1] > 4) { //Just if it is longer than one IP
				dns[1] = *((uint32_t *)(options + i + 2 + 4));
			}
			break;
		case DHCP_TYPE_DOMAIN_NAME:
			//FIXME Variable length..try to guess
			break;
		case DHCP_TYPE_MESSAGE:
			//Probably Offer, but doesn't really matter
			sent_offer = 255; //Stop sending discovery
			break;
		case DHCP_TYPE_SERVER_ID: //DHCP Server Identifier
			server = *((uint32_t *)(options + i + 2));
			break;
		default: //Not known option
			break;
		}
		i += options[i + 1] + 2;
	}
	info = dhcp_getmem();
	info->server_IP = server;
	info->router_IP = router;
	info->dnsp = dns[0];
	info->dnss = dns[1];
	info->mask = mask;
	//FIXME change shell
}
