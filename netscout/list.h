#ifndef __NETSCOUT_LIST_H__
#define __NETSCOUT_LIST_H__

#include <stdlib.h>
#include <string.h>

#define list_ether_add_uniq(uniq) ((struct stat_ether *) (list_add_uniq(&list_ether, sizeof(struct stat_ether), (uint8_t *) uniq, 6) ))
#define list_ip_add_uniq(uniq) ((struct stat_ip *) (list_add_uniq(&list_ip, sizeof(struct stat_ip), (uint8_t *) &uniq, 4) ))
#define list_wifi_add_uniq(uniq) ((struct stat_wifi *) (list_add_uniq(&list_wifi, sizeof(struct stat_wifi), (uint8_t *) uniq, 6)))

#include "../misc/list.h"

#endif

