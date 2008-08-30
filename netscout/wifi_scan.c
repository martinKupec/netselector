#include <stdio.h>
#include <iwlib.h>
#include <sys/select.h>
#include <sys/time.h>

static int skfd, we_ver;
static struct wireless_scan_head wsh;

int wifi_scan_init(void) {
	skfd = iw_sockets_open();
	we_ver = iw_get_kernel_we_version();
	return 0;
}

int wifi_scan(void) {
	struct wireless_scan *iter, *tmp;
	int delay;

	delay = iw_process_scan(skfd, "eth2", we_ver, &wsh);
	if(delay != 0) {
		return delay;
	}
	wsh.retry--;
	for(iter = wsh.result; iter != NULL; iter = tmp) {
		printf("Essid %s Quality %d -%d/%d\n", iter->b.essid, iter->stats.qual.qual, 255 - iter->stats.qual.level, iter->stats.qual.noise);
		tmp = iter->next;
		free(iter);
	}
	return 0; 
}
