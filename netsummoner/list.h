#ifndef __NETSUMMONER_LIST_H__
#define __NETSUMMONER_LIST_H__

#include <stdlib.h>
#include <string.h>

#define list_network_add(n) (struct network *) (list_add_after(list_network.head.prev, sizeof(struct network)))

#include "../misc/list.h"

#endif

