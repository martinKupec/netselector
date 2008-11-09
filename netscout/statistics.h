#ifndef __NETSCOUT_STATISTICS_H__
#define __NETSCOUT_STATISTICS_H__

#include "lib/netselector.h"

#define SHOW_TIME(time) time / 1000, time % 1000

void statistics_nbns(const struct info_field *info);
unsigned statistics_dhcps(const struct info_field *info, bool oneline);
unsigned statistics_stp(const struct info_field *info, bool oneline);
unsigned statistics_cdp(const struct info_field *info, bool oneline);
void statistics_eth_based(void);
void statistics_wifi_based(void);
void statistics_ip(const struct info_field *info);

void statistics_offer(void);

#endif

