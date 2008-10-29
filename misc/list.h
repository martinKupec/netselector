#ifndef __MISC_LIST_H__
#define __MISC_LIST_H__

#include <stdlib.h>
#include <string.h>

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

static inline void *list_add_uniq(list *l, const size_t size, const uint8_t *uniq, const size_t uniq_size) {
	node *n;
	int cmp;

	for(n = l->head.next; n != &(l->head); n = n->next) {
		cmp = memcmp((uint8_t *)(n + 1), uniq, uniq_size);
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
	memcpy(((uint8_t *)(n)), uniq, uniq_size);
	return n;
}

static inline void list_init(list *l) {
	l->head.prev = &(l->head);
	l->head.next = &(l->head);
}

static inline void list_remove(node *n) {
	(n - 1)->prev->next = (n - 1)->next;
	(n - 1)->next->prev = (n - 1)->prev;
	free(n - 1);
}

#define LIST_WALK(n, l) for(n = (void *)((l)->head.next + 1); (struct node *)(n) != (&((l)->head) + 1);\
							n = (void *) ((((struct node *) (n)) - 1)->next + 1))

#endif

