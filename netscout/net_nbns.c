#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <netinet/in.h>

#include "netscout.h"
#include "network.h"
#include "list.h"
#include "dhcpc.h"

static void sprint_nbname(char *buf, const unsigned char *name) {
	int i;

	for(i = 0; i < 16; i++) {
		buf[i] = ((name[2*i] - 'A') << 4) + (name[2*i + 1] - 'A');
	}
}

unsigned net_hndl_nbns(const uint8_t *pkt, shell *sh) {
	struct proto_nbname *info = nbname_getmem();

	sprint_nbname(info->name, pkt + 13);

	sh->from.higher_type = IP_TYPE_NBNS;
	sh->from.higher_data = info;
	sh->to.higher_type = IP_TYPE_NONE;
	sh->to.higher_data = NULL;
	return 0;
}

