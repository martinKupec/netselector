#ifndef __LIB_WIFI_H__
#define __LIB_WIFI_H__

#include <stdint.h>

int wifi_scan_init(const char *dev);
int wifi_scan(score_callback score_fnc, uint64_t start_time);

#endif

