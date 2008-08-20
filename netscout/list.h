#include <stdlib.h>

#define list_ether_add_tail() ((struct stat_ether *) (list_add_tail(&list_ether, sizeof(struct stat_ether))))
#define list_ether_add_uniq(uniq) ((struct stat_ether *) (list_add_uniq(&list_ether, sizeof(struct stat_ether), 0, uniq, 6) ))

typedef struct node {
	struct node *prev;	
	struct node *next;	
} node;

typedef struct list {
	struct node head;
} list;

static inline void *list_add_tail(list *l, size_t size) {
	node *n = (node *) malloc(size + sizeof(node) );
	
	n->prev = l->head.prev;
	n->next = &(l->head);
	l->head.prev->next = n;
	l->head.prev = n;
	return n + 1;
}

static inline void *list_add_uniq(list *l, size_t size, uint8_t offset, uint8_t *uniq, size_t uniq_size) {
	node *n;

	for(n = l->head.next; n != &(l->head); n = n->next) {
		if(!memcmp((uint8_t *)(n + 1) + offset, uniq, uniq_size)) {
			return n + 1;
		}
	}
	n = list_add_tail(l, size);
	bzero((uint8_t *)(n), size);
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


#define LIST_WALK(n, l) for(n = (void *)((l)->head.next + 1); (node *)(n) != (&((l)->head) + 1);\
							n = (void *) ((((node *) (n)) - 1)->next + 1))
