#ifndef __NETSCOUT_WIFI_H__
#define __NETSCOUT_WIFI_H__

#include <stdint.h>

int wifi_scan_init(const char *dev);
int wifi_scan(uint64_t start_time);

#endif

