#ifndef __NETSCOUT_STATISTICS_H__
#define __NETSCOUT_STATISTICS_H__

#define SHOW_TIME(time) time / 1000, time % 1000
#define IPQUAD(x) ((unsigned char *)&(x))[0], ((unsigned char *)&(x))[1], ((unsigned char *)&(x))[2], ((unsigned char*)&(x))[3]

void statistics_eth_based(void);
void statistics_wifi_based(void);

void statistics_offer(void);

#endif

