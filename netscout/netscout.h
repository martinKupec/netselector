

#define _GNU_SOURCE

#ifdef __GNUC__

#define UNUSED __attribute__((unused))
#define PACKED __attribute__((packed))

#else

#define UNUSED
#define PACKED

#endif

#include <stdint.h>

extern struct list list_ether, list_ip;

typedef struct shell {
	const uint8_t *packet;
	uint32_t time;
	void *lower_from;
	void *lower_from_args;
	void *lower_to;
	void *lower_to_args;
} shell;

typedef struct stat_ether {
	uint8_t addr[6];

	uint32_t time_count;
	uint32_t *time;
} stat_ether;

typedef struct stat_ip {
	uint8_t addr[4];

	struct stat_ether *ether;
} stat_ip;

typedef struct stat_nbname {
	char name[16];
	
	struct stat_ip *ip;
} stat_nbname;

typedef struct stat_cdp {
	uint8_t id[8];
	uint8_t ip_addr[4];

	struct stat_ether *ether;
} stat_cdp;

typedef struct stat_stp {
	uint8_t root[8];
	uint8_t bridge[8];
	uint16_t port;

	struct stat_ether *ether;
} stat_stp;

