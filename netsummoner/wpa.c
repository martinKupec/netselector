#include <stddef.h>
#include <string.h>
#include "wpa_ctrl.h"
#include "netsummoner.h"
#include "wpa.h"

#define MSG_LEN	1024

struct wpa_ctrl *wpa_ctl;

static int wpa_get_id(const char *list, const char *ssid) {
	char *line;
	line = strstr(list, ssid);
	if(!line) {
		return -1;
	}
	while(*(--line) != '\n')
		;
	line++;
	return atoi(line);
}

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

int wpa_connect(const char *ssid) {
	int ret, nid;
	size_t len = MSG_LEN;
	char msg[MSG_LEN];

	ret = wpa_ctrl_request(wpa_ctl, "LIST_NETWORKS", 13, msg, &len, NULL);
	msg[len - 1] = '\0';
	nid = wpa_get_id(msg, ssid);
	if(nid < 0) {
		return 1;
	}
	printf("Network ID %d\n", nid);

	ret = sprintf(msg, "SELECT_NETWORK %d", nid);
	len = MSG_LEN;
	ret = wpa_ctrl_request(wpa_ctl, msg, ret, msg, &len, NULL);
	msg[len - 1] = '\0';
	if(!strcmp("OK", msg)) {
		printf("Network %s selected\n", ssid);
	} else {
		printf("request returned %d and %s\n", ret, msg);
		return 2;
	}
	len = MSG_LEN;
	ret = wpa_ctrl_request(wpa_ctl, "REASSOCIATE", 11, msg, &len, NULL);
	msg[len - 1] = '\0';
	if(!strcmp("OK", msg)) {
		printf("Associating...\n");
	} else {
		printf("request returned %d and %s\n", ret, msg);
		return 2;
	}
	return 0;
}

int wpa_disconnect(void) {
	return 0;
}

int wpa_message(void) {
	size_t len = MSG_LEN - 1;
	char msg[MSG_LEN];

	//i = wpa_ctrl_pending(wpa_ctl); //it just select...so no need if i just did it

	if(wpa_ctrl_recv(wpa_ctl, msg, &len)) {
		fprintf(stderr, "WPA recv failed\n");
		return 2;
	}
	msg[len] = '\0';
	printf("received: %s\n", msg);
	if(strstr(msg, WPA_EVENT_CONNECTED)) {
		printf("CONNECTED\n");
		return 0;
	}
	return 1;
}

void wpa_close(void) {
	if(wpa_ctrl_detach(wpa_ctl)) {
		fprintf(stderr, "WPA detach failed\n");
	}
	wpa_ctrl_close(wpa_ctl);
}

