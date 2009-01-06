#include "arbiter.h"
#include "netsummoner.h"
#include "configuration.tab.h"
#include "lib/netselector.h"

struct network *arbiter(const struct arbiter_queue *queue) {
	struct network *nnode;

	LIST_WALK(nnode, &list_network) {
		unsigned i;
		unsigned score = 0, new_score = 0;

		for(i = 0; i < nnode->count; i++) {
			struct rule_set *rule = nnode->rules + i;

			if(rule->matched) {
				score += rule->score;
			} else {
				unsigned j;
				bool unmatched = false;;

				for(j = 0; j < rule->count; j++) {
					struct rule *item = rule->items + j;

					if(item->matched) {
						continue;
					}
					switch(rule->type) {
					case EAP:
					case WLCCP:
					case GATEWAY:
					case DHCPS:
					case DNS:
						switch(item->type) {
						case MAC:
							if(queue->enode_t && !memcmp(item->data, queue->enode_t->mac, 6)) {
								item->matched = true;
								printf("Network %s matched MAC - %d\n", nnode->name, rule->type);
							} else if(queue->enode_f && !memcmp(item->data, queue->enode_f->mac, 6)) {
								item->matched = true;
								printf("Network %s matched MAC - %d\n", nnode->name, rule->type);
							} else {
								unmatched = true;
							}
							break;
						case IP:
							if(queue->inode_t && !memcmp(item->data, &(queue->inode_t->ip), 4)) {
								item->matched = true;
								printf("Network %s matched IP\n", nnode->name);
							} else if(queue->inode_f && !memcmp(item->data, &(queue->inode_f->ip), 4)) {
								item->matched = true;
								printf("Network %s matched IP\n", nnode->name);
							} else {
								unmatched = true;
							}
							break;
						default:
								unmatched = true;
								break;
						}
						break;
					case CDP:
						switch(item->type) {
						case ID:
							if(queue->enode_f && (queue->enode_f->info->type == ETH_TYPE_CDP) && 
									!strcpy(item->data,
										(char *) (((struct proto_cdp *) (queue->enode_f->info))->did))) {
								item->matched = true;
								printf("Network %s matched CDP ID\n", nnode->name);
							} else {
								unmatched = true;
							}
							break;
						default:
							unmatched = true;
							break;
						}
						break;
					case STP:
						switch(item->type) {
						case ROOT:
							if(queue->enode_f && (queue->enode_f->info->type == ETH_TYPE_STP) && 
									!memcmp(item->data,
										((struct proto_stp *) (queue->enode_f->info->data))->root, 8)) {
								item->matched = true;
								printf("Network %s matched STP ROOT\n", nnode->name);
							} else {
								unmatched = true;
							}
							break;
						default:
							unmatched = true;
							break;
						}
						break;
					case NBNS:
						switch(item->type) {
						case NAME:
							if(queue->inode_f && (queue->inode_f->info->type == IP_TYPE_NBNS) && 
									!strcpy(item->data,
										(char *) (((struct proto_nbname *) (queue->inode_f->info))->name))) {
								item->matched = true;
								printf("Network %s matched NBNS NAME\n", nnode->name);
							} else {
								unmatched = true;
							}
							break;
						default:
							unmatched = true;
							break;
						}
						break;
					case WIFI:
						switch(item->type) {
						case MAC:
							if(queue->wnode && !memcmp(item->data, queue->wnode->mac, 6)) {
								item->matched = true;
								printf("Network %s matched WIFI MAC\n", nnode->name);
							} else {
								unmatched = true;
							}
							break;
						case ESSID:
							if(queue->wnode && !strcmp(item->data, (char *) queue->wnode->essid)) {
								item->matched = true;
								printf("Network %s matched WIFI ESSID\n", nnode->name);
							} else {
								unmatched = true;
							}
							break;
						default:
							unmatched = true;
							break;
						}
						break;
					}
				}
				if(!unmatched) {
					rule->matched = true;
					new_score += rule->score;
				}
			}
		}
		if((score + new_score) >= nnode->target_score) {
			if(new_score) {
				printf("Network %s won!\n", nnode->name);
			}
			return nnode;
		}
	}
	return NULL;
}

