#include <stddef.h>
#include <string.h>
#include "wpa_ctrl.h"
#include "netsummoner.h"
#include "wpa.h"

#define MSG_LEN	1024

struct wpa_ctrl *wpa_ctl;

struct module_info module_wpa;

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

static int wpa_callback(void *arg UNUSED) {
	int ret;

	ret = wpa_message();
	return 0;
}


int wpa_init(const char *iface) {
	char ctrl_path[100] = "/var/run/wpa_supplicant/";

	strcat(ctrl_path, iface);
	wpa_ctl = wpa_ctrl_open(ctrl_path);
	if(!wpa_ctl) {
		return -1;
	}
	if(wpa_ctrl_attach(wpa_ctl)) {
		return -2;
	}
	module_wpa.fnc = wpa_callback;
	module_wpa.arg = NULL;
	module_wpa.fd = wpa_ctrl_get_fd(wpa_ctl); 
	module_wpa.timeout = -2;
	return module_wpa.fd;
}

int wpa_connect(const char *ssid) {
	int ret, nid;
	size_t len = MSG_LEN - 1;
	char msg[MSG_LEN];

	ret = wpa_ctrl_request(wpa_ctl, "LIST_NETWORKS", 13, msg, &len, NULL);
	msg[len - 1] = '\0';
	nid = wpa_get_id(msg, ssid);
	if(nid < 0) {
		printf("MSG: %s\n SSID: %s\n", msg, ssid);
		return 1;
	}

	wpa_disconnect();

	ret = sprintf(msg, "SELECT_NETWORK %d", nid);
	len = MSG_LEN - 1;
	ret = wpa_ctrl_request(wpa_ctl, msg, ret, msg, &len, NULL);
	msg[len - 1] = '\0';
	if(strcmp("OK", msg)) {
		printf("request returned %d and %s\n", ret, msg);
		return 2;
	}
	len = MSG_LEN - 1;
	ret = wpa_ctrl_request(wpa_ctl, "RECONNECT", 9, msg, &len, NULL);
	msg[len - 1] = '\0';
	if(strcmp("OK", msg)) {
		printf("request returned %d and %s\n", ret, msg);
		return 2;
	}
	printf("Network %s selected\n", ssid);
	return 0;
}

int wpa_disconnect(void) {
	char msg[] = "DISCONNECT";
	int ret;
	size_t len = MSG_LEN - 1;

	ret = wpa_ctrl_request(wpa_ctl, msg, sizeof(msg), msg, &len, NULL);
	msg[len - 1] = '\0';
	if(strcmp("OK", msg)) {
		printf("request DISCONNECT returned %d and %s\n", len, msg);
		return 1;
	}
	return 0;
}

int wpa_message(void) {
	size_t len = MSG_LEN - 1;
	char msg[MSG_LEN];
	int i;

	i = wpa_ctrl_pending(wpa_ctl); //it just select...so no need if i just did it
	if(i < 1) {
		printf("WPA NOTHING TO DO\n");
		return 1;
	}

	if(wpa_ctrl_recv(wpa_ctl, msg, &len)) {
		fprintf(stderr, "WPA recv failed\n");
		return 2;
	}
	msg[len] = '\0';
	printf("received: %s\n", msg);
	if(strstr(msg, WPA_EVENT_CONNECTED)) {
		if(register_module(&module_wpa)) {
			fprintf(stderr, "Unable to register module WPA\n");
			return 3;
		} else {
			printf("CONNECTED\n");
			return 0;
		}
	}
	if(strstr(msg, WPA_EVENT_DISCONNECTED)) {
		printf("DISCONNECTED\n");
	}
	return 1;
}

void wpa_close(void) {
	if(wpa_ctrl_detach(wpa_ctl)) {
		fprintf(stderr, "WPA detach failed\n");
	}
	wpa_ctrl_close(wpa_ctl);
}

