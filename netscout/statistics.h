#ifndef __NETSCOUT_STATISTICS_H__
#define __NETSCOUT_STATISTICS_H__

#include "netscout.h"

#define SHOW_TIME(time) time / 1000, time % 1000
#define IPQUAD(x) ((unsigned char *)&(x))[0], ((unsigned char *)&(x))[1], ((unsigned char *)&(x))[2], ((unsigned char*)&(x))[3]

unsigned statistics_dhcps(const struct info_field *info, bool oneline);
unsigned statistics_stp(const struct info_field *info, bool oneline);
unsigned statistics_cdp(const struct info_field *info, bool oneline);
void statistics_eth_based(void);
void statistics_wifi_based(void);

void statistics_offer(void);

#endif

