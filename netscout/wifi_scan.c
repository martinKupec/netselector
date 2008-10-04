#include <stdio.h>
#include <iwlib.h>
#include <sys/select.h>
#include <sys/time.h>

#include "netscout.h"
#include "wifi.h"
#include "list.h"

static int skfd, we_ver;
static struct wireless_scan_head wsh;

int wifi_scan_init(void) {
	skfd = iw_sockets_open();
	we_ver = iw_get_kernel_we_version();
	return 0;
}

int wifi_scan(uint64_t start_time) {
	struct stat_wifi *node;
	struct wireless_scan *iter, *tmp;
	struct timeval time;
	uint32_t now;
	int delay;

	delay = iw_process_scan(skfd, "eth2", we_ver, &wsh);
	if(delay != 0) {
		return delay;
	}
	wsh.retry--; //Work-around fail-safe of iwlib

	gettimeofday(&time, NULL);
	now = (uint32_t) (time.tv_sec * 1000 + (time.tv_usec / 1000)) - start_time;
	for(iter = wsh.result; iter != NULL; iter = tmp) {
		node = list_wifi_add_uniq(iter->b.essid);
		if(node->quality == NULL) {
			node->quality = (uint8_t *) malloc(sizeof(uint8_t) * 16);
			node->time = (uint32_t *) malloc(sizeof(uint32_t) * 16);
		} else {
			if((node->quality_count & 0x0F) == 0x0F) {
				node->quality = (uint8_t *) realloc(node->quality, sizeof(uint8_t) * (node->quality_count + 16));
				node->time = (uint32_t *) realloc(node->time, sizeof(uint32_t) * (node->quality_count + 16));
			}
		}
		node->quality[node->quality_count] = iter->stats.qual.qual;
		node->time[node->quality_count++] = now;

		tmp = iter->next;
		free(iter);
	}
	return 0; 
}
