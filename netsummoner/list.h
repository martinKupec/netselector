#ifndef __NETSUMMONER_LIST_H__
#define __NETSUMMONER_LIST_H__

#include <stdlib.h>
#include <string.h>

#define list_network_add() (struct network *) (list_add_after(list_network.head.prev, sizeof(struct network)))
#define list_action_add() (struct action *) (list_add_after(list_action.head.prev, sizeof(struct action)))
#define list_assembly_add() (struct assembly *) (list_add_after(list_assembly.head.prev, sizeof(struct assembly)))

#include "../misc/list.h"

#endif

