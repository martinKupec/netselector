#include <stdio.h>
#include <iwlib.h>
#include <sys/select.h>
#include <sys/time.h>

int wifi_scan(void) {
	struct wireless_scan_head wsh;
	struct wireless_scan *iter, *tmp;
	int we_ver = iw_get_kernel_we_version();
	int delay, skfd;

	skfd = iw_sockets_open();
	while(1) {
		delay = iw_process_scan(skfd, "eth2", we_ver, &wsh);
		if(delay <= 0) {
			break;
		}
		printf("Delay: %d\n", delay);
		usleep(delay * 1000);
	}
	for(iter = wsh.result; iter != NULL; iter = tmp) {
		printf("Essid %s Quality %d -%d/%d\n", iter->b.essid, iter->stats.qual.qual, 255 - iter->stats.qual.level, iter->stats.qual.noise);
		tmp = iter->next;
		free(iter);
	}
	return 0; 
}
