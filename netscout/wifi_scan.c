#include <stdio.h>
#include <iwlib.h>
#include <sys/select.h>
#include <sys/time.h>

#include "netscout.h"
#include "wifi.h"
#include "list.h"

static int skfd, we_ver;
static char *wifidevice;
static struct wireless_scan_head wsh;

int wifi_scan_init(const char *dev) {
	skfd = iw_sockets_open();
	we_ver = iw_get_kernel_we_version();
	wifidevice = (char *) dev;
	return 0;
}

int wifi_scan(const uint64_t start_time) {
	struct stat_wifi *node;
	struct wireless_scan *iter, *tmp;
	struct timeval time;
	uint32_t now;
	int delay;

	delay = iw_process_scan(skfd, wifidevice, we_ver, &wsh);
	if(delay != 0) {
		return delay;
	}
	wsh.retry--; //Work-around fail-safe of iwlib

	gettimeofday(&time, NULL);
	now = (uint32_t) (time.tv_sec * 1000 + (time.tv_usec / 1000)) - start_time;
	for(iter = wsh.result; iter != NULL; iter = tmp) {
		node = list_wifi_add_uniq(iter->ap_addr.sa_data);
		if(node->quality == NULL) {
			memcpy(node->essid, iter->b.essid, 16);
			node->quality = (uint8_t *) malloc(sizeof(uint8_t) * 16);
			node->time = (uint32_t *) malloc(sizeof(uint32_t) * 16);
		} else {
			if((node->count & 0x0F) == 0x0F) {
				node->quality = (uint8_t *) realloc(node->quality, sizeof(uint8_t) * (node->count + 16));
				node->time = (uint32_t *) realloc(node->time, sizeof(uint32_t) * (node->count + 16));
			}
		}
		node->quality[node->count] = iter->stats.qual.qual;
		node->time[node->count++] = now;

		tmp = iter->next;
		free(iter);
	}
	return 0; 
}
