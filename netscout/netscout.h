

#define _GNU_SOURCE

#ifdef __GNUC__

#define UNUSED __attribute__((unused))
#define PACKED __attribute__((packed))

#else

#define UNUSED
#define PACKED

#endif

#include <stdint.h>

struct ns {
	uint8_t *packet;
	uint64_t time;
};

struct knowleadge {
	uint64_t time;
	uint16_t type;
	uint8_t *data;
};

struct stat_ether {
	uint8_t addr[6];

	uint64_t time;
};

struct stat_ip {
	uint8_t addr[4];

	struct stat_ether *ether;
};

struct stat_nbname {
	char name[16];
	
	struct stat_ip *ip;
};

struct stat_cdp {
	uint8_t id[8];
	uint8_t ip_addr[4];

	struct stat_ether *ether;
};

struct stat_stp {
	uint8_t root[8];
	uint8_t bridge[8];
	uint16_t port;

	struct stat_ether *ether;
};

