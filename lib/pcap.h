#ifndef __NETSELECTOR_PCAP_H__
#define __NETSELECTOR_PCAP_H__

#include <pcap.h>

#include "lib/netselector.h"

struct net_pcap {
	const char *dev;
	const char *file;
	bool promiscuous;
	const score_callback score_fnc;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *hndl;
};

int pcap_init(struct net_pcap *np);

#endif

