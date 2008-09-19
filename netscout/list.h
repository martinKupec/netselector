#include <stdlib.h>

#define list_ether_add_tail() ((struct stat_ether *) (list_add_tail(&list_ether, sizeof(struct stat_ether))))
#define list_ether_add_uniq(uniq) ((struct stat_ether *) (list_add_uniq(&list_ether, sizeof(struct stat_ether), 0, uniq, 6) ))

#define list_ip_add_uniq(uniq) ((struct stat_ip *) (list_add_uniq(&list_ip, sizeof(struct stat_ip), 0, (uint8_t *) &uniq, 4) ))
#define list_nbname_add_uniq(uniq) ((struct stat_nbname *) (list_add_uniq(&list_nbname, sizeof(struct stat_nbname), 0, (uint8_t *)uniq, 16) ))
#define list_cdp_add_uniq(uniq) ((struct stat_cdp *) (list_add_uniq(&list_cdp, sizeof(struct stat_cdp), 0, (uint8_t *) uniq, 16)))
#define list_stp_add_uniq(uniq) ((struct stat_stp *) (list_add_uniq(&list_stp, sizeof(struct stat_stp), 0, uniq, 8)))
#define list_wifi_add_uniq(uniq) ((struct stat_wifi *) (list_add_uniq(&list_wifi, sizeof(struct stat_wifi), 0, (uint8_t *) uniq, 16)))

typedef struct node {
	struct node *prev;	
	struct node *next;	
} node;

typedef struct list {
	struct node head;
} list;

static inline void *list_add_after(node *a, size_t size) {
	node *n = (node *) malloc(size + sizeof(node) );
	
	n->prev = a;
	n->next = a->next;
	a->next->prev = n;
	a->next = n;
	return n + 1;
}

static inline void *list_add_tail(list *l, size_t size) {
	return list_add_after(l->head.prev, size);
}

static inline void *list_add_uniq(list *l, const size_t size, const uint8_t offset, const uint8_t *uniq, const size_t uniq_size) {
	node *n;
	int cmp;

	for(n = l->head.next; n != &(l->head); n = n->next) {
		cmp = memcmp((uint8_t *)(n + 1) + offset, uniq, uniq_size);
		if(cmp == 0) {
			return n + 1;
		} else if(cmp > 0) {
			n = list_add_after(n->prev, size);
			break;
		}
	}
	if(n == &(l->head)) {
		n = list_add_tail(l, size);
	}
	bzero((uint8_t *)(n), size);
	memcpy(((uint8_t *)(n)) + offset, uniq, uniq_size);
	return n;
}

static inline void list_init(list *l) {
	l->head.prev = &(l->head);
	l->head.next = &(l->head);
}

static inline void list_remove(node *n) {
	n->prev->next = n->next;
	n->next->prev = n->prev;
	free(n);
}

static inline void filter_list(list *l, uint8_t offset, size_t size) {
	node *a, *b;

	for(a = l->head.next; a != &(l->head); a = a->next) {
		for(b = a->next; b != &(l->head); b = b->next) {
			if(!memcmp((uint8_t *)(a + 1) + offset, (uint8_t *)(b + 1) + offset, size)) {
				list_remove(b);
			}
		}
	}
}


#define LIST_WALK(n, l) for(n = (void *)((l)->head.next + 1); (struct node *)(n) != (&((l)->head) + 1);\
							n = (void *) ((((struct node *) (n)) - 1)->next + 1))
