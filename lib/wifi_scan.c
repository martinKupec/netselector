#include <stdio.h>
#include <iwlib.h>
#include <sys/select.h>
#include <sys/time.h>

#include "lib/netselector.h"
#include "lib/wifi.h"
#include "lib/node_info.h"

static int skfd, we_ver;
static char *wifidevice;
static struct wireless_scan_head wsh;

int wifi_scan_init(const char *dev) {
	skfd = iw_sockets_open();
	we_ver = iw_get_kernel_we_version();
	wifidevice = (char *) dev;
	return 0;
}

int wifi_scan(score_callback score_fnc, const uint64_t start_time) {
	struct stat_wifi *node;
	struct wireless_scan *iter, *tmp;
	struct timeval time;
	struct shell_exchange she;
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
		node = get_node_wifi((uint8_t *) iter->ap_addr.sa_data);
		memcpy(node->essid, iter->b.essid, 16);
		she.lower_node = node;
		she.higher_type = WIFI_TYPE_QUALITY;
		she.higher_data = (void *) ((uint32_t) iter->stats.qual.qual);
		score_fnc(wifi_node_set_info(&she, now));

		tmp = iter->next;
		free(iter);
	}

	return 0; 
}

