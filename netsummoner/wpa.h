#ifndef __NETSUMONNER_WPA_H__
#define __NETSUMMONER_WPA_H__

int wpa_init(const char *iface);
int wpa_message(void);
int wpa_connect(const char *ssid, struct network *net);
int wpa_disconnect(void);
void wpa_close(void);

#endif
