#include <stdlib.h>

#define list_ether_add_tail() ((struct stat_ether *) (list_add_tail(&list_ether, sizeof(struct stat_ether))))

typedef struct node {
	struct node *prev;	
	struct node *next;	
} node;

typedef struct list {
	struct node head;
} list;

static inline void *list_add_tail(list *l, size_t size) {
	node *n = (node *) malloc(size + sizeof(list *) );
	
	n->prev = l->head.prev;
	n->next = &(l->head);
	l->head.prev->next = n;
	l->head.prev = n;
	return n + 1;
}

static inline void list_init(list *l) {
	l->head.prev = &(l->head);
	l->head.next = &(l->head);
}

#define LIST_WALK(n, l) for(n = (void *)((l)->head.next + 1); (node *)(n) != (&((l)->head) + 1);\
							n = (void *) ((((node *) (n)) - 1)->next + 1))
