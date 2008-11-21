#ifndef __LIB_NETSELECTOR_H__
#define __LIB_NETSELECTOR_H__

#define _GNU_SOURCE

#ifdef __GNUC__

#define UNUSED __attribute__((unused))
#define PACKED __attribute__((packed))

#else

#define UNUSED
#define PACKED

#endif

#include <stdbool.h>
#include <stdint.h>
#include <pcap.h>

#define IPQUAD(x) ((unsigned char *)&(x))[0], ((unsigned char *)&(x))[1], ((unsigned char *)&(x))[2], ((unsigned char*)&(x))[3]

enum {
	NODE_TYPE_ETH,
	NODE_TYPE_IP,
	NODE_TYPE_WIFI
};

enum {
	ETH_TYPE_NONE,
	ETH_TYPE_IP,
	ETH_TYPE_REVARP,
	ETH_TYPE_VLAN,
	ETH_TYPE_EAP,
	ETH_TYPE_CDP,
	ETH_TYPE_WLCCP,
	ETH_TYPE_STP,
	ETH_TYPE_STP_UNKNOWN,
	ETH_TYPE_CDP_UNKNOWN,
	ETH_TYPE_SNAP_UNKNOWN,
	ETH_TYPE_ARP_UNKNOWN,
	ETH_TYPE_LLC_UNKNOWN,
	ETH_TYPE_UNKNOWN,
	ETH_TYPE_LAST,

	IP_TYPE_NONE,
	IP_TYPE_ARP,
	IP_TYPE_ICMP,
	IP_TYPE_TCP,
	IP_TYPE_UDP,
	IP_TYPE_SSDP,
	IP_TYPE_NBNS,
	IP_TYPE_DHCPC,
	IP_TYPE_DHCPS,
	IP_TYPE_DNSS,
	IP_TYPE_DNSC,
	IP_TYPE_UNKNOWN,
	IP_TYPE_LAST,
	INFO_TYPE_LAST
};

struct shell_exchange {
	void *lower_node;
	uint32_t higher_type;
	void *higher_data;
};

typedef struct shell {
	uint8_t const *packet;
	uint32_t time;
	struct shell_exchange to, from;
} shell;

struct info_field {
	uint32_t type;
	void *data;
	uint32_t count;
	uint32_t time_first;
	uint32_t time_last;
};

typedef struct stat_ether {
	uint8_t mac[6];

	unsigned count;
	struct info_field *info;
} stat_ether;

typedef struct stat_ip {
	uint32_t ip;

	struct stat_ether *ether;
	unsigned count;
	struct info_field *info;
} stat_ip;

typedef struct stat_wifi {
	uint8_t mac[6];

	uint8_t essid[16];
	uint8_t count;
	uint8_t *quality;
	uint32_t *time;
} stat_wifi;

typedef struct proto_nbname {
	char name[17];
} proto_nbname;
#define nbname_getmem()	((struct proto_nbname *) (malloc(sizeof(struct proto_nbname))))

typedef struct proto_cdp {
	uint8_t did[17];
	uint8_t port[11];
	uint8_t ver[7];
	uint8_t plat[17];
} proto_cdp;
#define cdp_getmem()	((struct proto_cdp *) (malloc(sizeof(struct proto_cdp))))

typedef struct proto_stp {
	uint8_t bridge[8];
	uint8_t root[8];
	uint16_t port;
} proto_stp;
#define stp_getmem()	((struct proto_stp *) (malloc(sizeof(struct proto_stp))))

typedef struct proto_dhcp {
	uint32_t server_IP;
	uint32_t router_IP;
	uint32_t dnsp, dnss;
	uint32_t mask;
} proto_dhcp;
#define dhcp_getmem()	((struct proto_dhcp *) (malloc(sizeof(struct proto_dhcp))))

#define ether_node_set_info(ex, time) node_set_info(ex, time, NODE_TYPE_ETH)
#define ip_node_set_info(ex, time) node_set_info(ex, time, NODE_TYPE_IP)
#define wifi_node_set_info(ex, time) node_set_info(ex, time, NODE_TYPE_WIFI)

typedef struct stat_ip *(* callback_ip)(const uint32_t);
typedef struct stat_ether *(* callback_ether)(const uint8_t *);
typedef struct stat_wifi *(* callback_wifi)(const uint8_t *);

typedef void (*score_callback)(const unsigned);

struct net_pcap {
	const char *dev;
	const char *file;
	const char *wifidev;
	bool dhcp_active;
	bool promiscuous;
	bool verbose;
	const score_callback score_fnc;
	char errbuf[PCAP_ERRBUF_SIZE];
	int err;
};

extern callback_ip get_node_ip;
extern callback_ether get_node_ether;
extern callback_wifi get_node_wifi;
extern bool show_received;

extern volatile int signal_stop;

void libnetselector_init(callback_ip ip, callback_ether ether, callback_wifi wifi, bool show);
int use_pcap(struct net_pcap *np);

#endif

