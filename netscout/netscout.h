

#define _GNU_SOURCE

#ifdef __GNUC__

#define UNUSED __attribute__((unused))
#define PACKED __attribute__((packed))

#else

#define UNUSED
#define PACKED

#endif

#include <stdint.h>

extern struct list list_ether, list_ip, list_nbname, list_cdp, list_stp;

typedef struct shell {
	const uint8_t *packet;
	uint32_t time;
	void *lower_from;
	void *lower_to;
} shell;

typedef struct stat_ether {
	uint8_t addr[6];

	uint32_t time_count;
	uint32_t *time;
} stat_ether;

typedef struct stat_ip {
	uint8_t addr[4];

	uint32_t ether_count;
	struct stat_ether **ether;
	uint32_t *time;
} stat_ip;

typedef struct stat_nbname {
	char name[16];
	
	uint32_t ip_count;
	struct stat_ip **ip;
	uint32_t *time;
} stat_nbname;

typedef struct stat_cdp {
	uint8_t did[16];
	uint8_t port[10];
	uint8_t ver[6];
	uint8_t plat[16];

	uint32_t ether_count;
	struct stat_ether **ether;
	uint32_t *time;
} stat_cdp;

typedef struct stat_stp {
	uint8_t bridge[8];
	uint8_t root[8];
	uint16_t port;

	uint32_t ether_count;
	struct stat_ether **ether;
	uint32_t *time;
} stat_stp;

