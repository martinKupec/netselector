#include <stddef.h>
#include "wpa_ctrl.h"
#include "netsummoner.h"
#include "wpa.h"

#define MSG_LEN	100

struct wpa_ctrl *wpa_ctl;

int wpa_init(void) {
	const char ctrl_path[] = "/var/run/wpa_supplicant/eth2";
	wpa_ctl = wpa_ctrl_open(ctrl_path);

	if(!wpa_ctl) {
		return -1;
	}
	if(wpa_ctrl_attach(wpa_ctl)) {
		return -2;
	}
	printf("wpa fd %d\n", wpa_ctrl_get_fd(wpa_ctl));
	return wpa_ctrl_get_fd(wpa_ctl);
}

int wpa_connect(void) {
	return 0;
}

int wpa_disconnect(void) {
	return 0;
}

int wpa_message(void) {
	int i;
	size_t len = MSG_LEN;
	char msg[MSG_LEN];

	//i = wpa_ctrl_pending(wpa_ctl); //it just select...so no need if i just did it

	if(i == -1) {
		fprintf(stderr, "WPA ask pending failed\n");
		return 1;
	}
	if(!i) {
		return 0;
	}
	if(wpa_ctrl_recv(wpa_ctl, msg, &len)) {
		fprintf(stderr, "WPA recv failed\n");
		return 2;
	}
	printf("received: %s\n", msg);
	return 0;
}

void wpa_close(void) {
	if(wpa_ctrl_detach(wpa_ctl)) {
		fprintf(stderr, "WPA detach failed\n");
	}
	wpa_ctrl_close(wpa_ctl);
}
