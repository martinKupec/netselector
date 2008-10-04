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

#include <stdint.h>

enum {
	NODE_TYPE_ETH,
	NODE_TYPE_IP,
	NODE_TYPE_WIFI
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

typedef void (hndl_t)(const uint8_t *pkt, shell *sh);

struct info_field { //Do not reorder
	uint32_t type;
	uint32_t time;
	void *data;
};

typedef struct stat_ether {
	uint8_t mac[6];

	unsigned count;
	struct info_field *info;
} stat_ether;

typedef struct stat_ip {
	uint8_t ip[4];

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

void node_set_info(const struct shell_exchange *ex, const uint32_t time, int node_type);

#endif

