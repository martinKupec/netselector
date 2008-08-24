#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "netscout.h"
#include "list.h"

#define SHOW_TIME(time) time / 1000, time % 1000

void stats_time(uint32_t *time, unsigned int count) {
		uint32_t avg;

		avg = time[count - 1] / count;
		printf("First %03u.%03u ", SHOW_TIME(time[0]));
		printf("Count %d ", count);
		printf("Avg %03u.%03u ", SHOW_TIME(avg));
}

void stats_ether(struct list *l) {
	struct stat_ether *node;

	LIST_WALK(node, l) {
		printf("Ether %02X:%02X:%02X:%02X:%02X:%02X ", node->addr[0], node->addr[1], node->addr[2],
			node->addr[3], node->addr[4], node->addr[5]);
		stats_time(node->time, node->time_count);
		printf("\n");
	}
}

void stats_ip(struct list *l) {
	struct stat_ip *node;
	unsigned int distinct = 0, from, i;

	LIST_WALK(node, l) {
		uint8_t last[6];

		printf("IP %d.%d.%d.%d\n", node->addr[0], node->addr[1], node->addr[2], node->addr[3]);
		bzero(last, 6);
		for(i = 0, from = 0; i < node->ether_count; i++) {
			if(memcmp(node->ether[i]->addr, last, 6)) {
				distinct++;
				memcpy(last, node->ether[i]->addr, 6);
				printf("        %02X:%02X:%02X:%02X:%02X:%02X ", node->ether[i]->addr[0],
						node->ether[i]->addr[1], node->ether[i]->addr[2], node->ether[i]->addr[3],
						node->ether[i]->addr[4], node->ether[i]->addr[5]);
				stats_time(node->time + from, i - from + 1);
				printf("\n");
				from = i;
			}
		}
	}
}
