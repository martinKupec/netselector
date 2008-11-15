#include "arbiter.h"
#include "netsummoner.h"
#include "configuration.tab.h"
#include "lib/netselector.h"

void arbiter(const struct arbiter_queue *queue) {
	struct network *nnode;

	LIST_WALK(nnode, &list_network) {
		unsigned i;
		unsigned score = 0;

		for(i = 0; i < nnode->count; i++) {
			struct rule_set *rule = nnode->rules + i;
			
			if(rule->matched) {
				score += rule->score;
			} else {
				unsigned j;
				bool unmatched = false;;

				switch(rule->type) {
				case EAP:
				case WLCCP:
				case GATEWAY:
				case DHCPS:
				case DNS:
					for(j = 0; j < rule->count; j++) {
						struct rule *item = rule->items + j;
	
						if(!item->matched) {
							switch(item->type) {
							case MAC:
								if(!memcmp(item->data, queue->enode_t->mac, 6)) {
									item->matched = true;
								} else if(!memcmp(item->data, queue->enode_f->mac, 6)) {
									item->matched = true;
								} else {
									unmatched = true;
								}
								break;
							case IP:
								if(!memcmp(item->data, &(queue->inode_t->ip), 4)) {
									item->matched = true;
								} else if(!memcmp(item->data, &(queue->inode_f->ip), 4)) {
									item->matched = true;
								} else {
									unmatched = true;
								}
								break;
							default:
								unmatched = true;
								break;
							}
						}
					}
					break;
				case CDP:
					for(j = 0; j < rule->count; j++) {
						struct rule *item = rule->items + j;
	
						if(!item->matched) {
							switch(item->type) {
							case ID:
								if((queue->enode_f->info->type == ETH_TYPE_CDP) && 
										!strcpy(item->data,
										(char *) (((struct proto_cdp *) (queue->enode_f->info))->did))) {
									item->matched = true;
								} else {
									unmatched = true;
								}
								break;
							default:
								unmatched = true;
								break;
							}
						}
					}
					break;
				case STP:
					for(j = 0; j < rule->count; j++) {
						struct rule *item = rule->items + j;
	
						if(!item->matched) {
							switch(item->type) {
							case ROOT:
								if((queue->enode_f->info->type == ETH_TYPE_STP) && 
										!memcmp(item->data,
										((struct proto_stp *) (queue->enode_f->info))->root, 8)) {
									item->matched = true;
								} else {
									unmatched = true;
								}
								break;
							default:
								unmatched = true;
								break;
							}
						}
					}
					break;
				case NBNS:
					for(j = 0; j < rule->count; j++) {
						struct rule *item = rule->items + j;
	
						if(!item->matched) {
							switch(item->type) {
							case NAME:
								if((queue->inode_f->info->type == IP_TYPE_NBNS) && 
										!strcpy(item->data,
										(char *) (((struct proto_nbname *) (queue->inode_f->info))->name))) {
									item->matched = true;
								} else {
									unmatched = true;
								}
								break;
							default:
								unmatched = true;
								break;
							}
						}
					}
					break;
				case WIFI:
					for(j = 0; j < rule->count; j++) {
						struct rule *item = rule->items + j;
	
						if(!item->matched) {
							switch(item->type) {
							case MAC:
								if(!memcmp(item->data, queue->wnode->mac, 6)) {
									item->matched = true;
								} else {
									unmatched = true;
								}
								break;
							case ESSID:
								if(!strcmp(item->data, (char *) queue->wnode->essid)) {
									item->matched = true;
								} else {
									unmatched = true;
								}
								break;
							default:
								unmatched = true;
								break;
							}
						}
					}
					break;
				}
				if(!unmatched) {
					rule->matched = true;
					score += rule->score;
				}
			}
		}
		if(score >= nnode->target_score) {
			printf("WON\n");
		}
	}
}

