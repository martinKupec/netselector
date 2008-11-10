#ifndef __NETSCOUT_STATISTICS_H__
#define __NETSCOUT_STATISTICS_H__

#include "lib/netselector.h"

void statistics_eth_based(void);
void statistics_wifi_based(void);
void statistics_ip(const struct info_field *info);

void statistics_offer(void);

#endif

