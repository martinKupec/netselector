#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <sys/select.h>

#include "lib/netselector.h"
#include "lib/pcap.h"
#include "lib/link.h"

typedef unsigned (*hndl_p)(const uint8_t *pkt, shell *sh);

struct catcher_args {
	score_callback fnc;
	hndl_p hndl;
	pcap_t *pcap_hndl;
};

static struct catcher_args cat_arg;
static struct module_info pcap_module = {
	.timeout = 0
};

/*
 * Pcap's catcher
 */
static void catcher(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {
	const struct catcher_args *arg = (const struct catcher_args *) args;
	const uint64_t now = hdr->ts.tv_sec * 1000 + (hdr->ts.tv_usec / 1000);
	shell sh;

	sh.time = (uint32_t)(now - start_time);
	sh.packet = pkt;
	arg->fnc(arg->hndl((const uint8_t *) pkt, &sh));
}

static int pcap_callback(struct catcher_args *arg) {
	int ret;

	ret = pcap_dispatch(arg->pcap_hndl, -1, catcher, (u_char *) arg);
	if(ret < 0) {
		//FIXME - return error??
		printf("Pcap error\n");
		return 7;
	}
	return 0;
}

/*
 * Sets datalink handler for datalink type
 */
static hndl_p set_datalink(const int link) {
	switch(link) {
	case DLT_EN10MB:
		return link_hndl_ether;
	}
	return NULL;
}

int pcap_init(struct net_pcap *np) {
	int dlink;

	if(np->file) {
		np->hndl = pcap_open_offline(np->file, np->errbuf);
		if (!np->hndl) {
			return 1;
		}
	} else if(np->dev) {
		np->hndl = pcap_open_live(np->dev, BUFSIZ, np->promiscuous, 250, np->errbuf);
		if (!np->hndl) {
			return 2;
		}
	} else {
		return 3;
	}

	cat_arg.pcap_hndl = np->hndl;
	cat_arg.fnc = np->score_fnc;
	dlink = pcap_datalink(np->hndl);
	if(!(cat_arg.hndl = set_datalink(dlink))) {
		return 4;
	}

	pcap_setnonblock(np->hndl, 1, np->errbuf);

	pcap_module.fnc = (dispatch_callback) pcap_callback;
	pcap_module.arg = &cat_arg;
	pcap_module.fd = pcap_get_selectable_fd(np->hndl);
	if(register_module(&pcap_module)) {
		return 5;
	}
	return 0;
}

