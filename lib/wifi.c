#include <stdio.h>
#include <iwlib.h>
#include <sys/time.h>

#include "lib/netselector.h"
#include "lib/wifi.h"
#include "lib/node_info.h"

struct wifi_args {
	int skfd;
	int we_ver;
	char *wifidevice;
	struct wireless_scan_head wsh;
	score_callback fnc;
};

static struct wifi_args wifi_arg;
static struct module_info module_wifi;

static int wifi_callback(struct wifi_args *arg) {
	struct stat_wifi *node;
	struct wireless_scan *iter, *tmp;
	struct timeval time;
	struct shell_exchange she;
	uint32_t now;
	int delay;

	delay = iw_process_scan(arg->skfd, arg->wifidevice, arg->we_ver, &(arg->wsh));
	if(delay != 0) {
		module_wifi.timeout = delay;
		return 0;
	}
	arg->wsh.retry--; //Work-around fail-safe of iwlib

	gettimeofday(&time, NULL);
	now = (uint32_t) (time.tv_sec * 1000 + (time.tv_usec / 1000)) - start_time;
	for(iter = arg->wsh.result; iter != NULL; iter = tmp) {
		node = get_node_wifi((uint8_t *) iter->ap_addr.sa_data);
		memcpy(node->essid, iter->b.essid, 16);
		she.lower_node = node;
		she.higher_type = WIFI_TYPE_QUALITY;
		she.higher_data = (void *) ((uint32_t) iter->stats.qual.qual);
		arg->fnc(wifi_node_set_info(&she, now));

		tmp = iter->next;
		free(iter);
	}
	arg->wsh.result = NULL;

	return 0; 
}

int wifi_init(char *dev, score_callback score_fnc) {
	wifi_arg.skfd = iw_sockets_open();
	if(wifi_arg.skfd < 0) {
		return 1;
	}
	wifi_arg.we_ver = iw_get_kernel_we_version();
	wifi_arg.wifidevice = dev;
	wifi_arg.fnc = score_fnc;

	module_wifi.fnc = (dispatch_callback) wifi_callback;
	module_wifi.arg = &wifi_arg;
	module_wifi.fd = wifi_arg.skfd;
	module_wifi.timeout = 1;
	if(register_module(&module_wifi)) {
		return 2;
	}
	return 0;
}

void wifi_deinit(void) {
	iw_sockets_close(wifi_arg.skfd);
	module_wifi.timeout = -3; //Unregister
}
