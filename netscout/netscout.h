#ifndef __NETSCOUT_NETSCOUT_H__
#define __NETSCOUT_NETSCOUT_H__

#define _GNU_SOURCE

#ifdef __GNUC__

#define UNUSED __attribute__((unused))
#define PACKED __attribute__((packed))

#else

#define UNUSED
#define PACKED

#endif

#ifndef bool
	#define bool _Bool
#endif

#include <stdint.h>

enum {
	NODE_TYPE_ETH,
	NODE_TYPE_IP,
	NODE_TYPE_WIFI
};

enum {
	ETH_TYPE_NONE,
	ETH_TYPE_IP,
	ETH_TYPE_ARP,
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

typedef unsigned (*hndl_p)(const uint8_t *pkt, shell *sh);

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
	char name[16];
} proto_nbname;
#define nbname_getmem()	((struct proto_nbname *) (malloc(sizeof(struct proto_nbname))))

typedef struct proto_cdp {
	uint8_t did[16];
	uint8_t port[10];
	uint8_t ver[6];
	uint8_t plat[16];
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

extern struct list list_ether, list_ip, list_wifi;

unsigned node_set_info(const struct shell_exchange *ex, const uint32_t time, int node_type);

#endif

