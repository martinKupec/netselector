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
#include "lib/link.h"
#include "lib/wifi.h"
#include "lib/dhcpc.h"

typedef unsigned (*hndl_p)(const uint8_t *pkt, shell *sh);

struct catcher_args {
	score_callback fnc;
	hndl_p hndl;
};

volatile int signal_stop = 0;

static uint64_t start_time;

callback_ip get_node_ip;
callback_ether get_node_ether;
callback_wifi get_node_wifi;
bool show_received;

void libnetselector_init(callback_ip ip, callback_ether ether, callback_wifi wifi, bool show) {
	get_node_ip = ip;
	get_node_ether = ether;
	get_node_wifi = wifi;
	show_received = show;
}

/*
 * Signal handler for terminating
 */
static void signal_hndl(int sig UNUSED) {
	signal_stop = 1;
	signal(SIGINT, SIG_DFL);
}

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

int use_pcap(struct net_pcap *np) {
	pcap_t *pcap_hndl;
	int dlink;
	struct timeval time;
	struct catcher_args cat_arg = { .fnc = np->score_fnc};

	signal(SIGINT, signal_hndl);

	if(np->file) {
		pcap_hndl = pcap_open_offline(np->file, np->errbuf);
		if (!pcap_hndl) {
			return 1;
		}
	} else if(np->dev) {
		pcap_hndl = pcap_open_live(np->dev, BUFSIZ, np->promiscuous, 250, np->errbuf);
		if (!pcap_hndl) {
			return 2;
		}
	} else {
		return 3;
	}
	dlink = pcap_datalink(pcap_hndl);
	if(!(cat_arg.hndl = set_datalink(dlink))) {
		np->err = dlink;
		return 4;
	}
	if(!np->file && np->wifidev) {
		if(wifi_scan_init(np->wifidev) > 0) {
			return 5;
		}
	}

	gettimeofday(&time, NULL);
	start_time = time.tv_sec * 1000 + (time.tv_usec / 1000);

	if(np->file) {
		pcap_dispatch(pcap_hndl, -1, catcher, (u_char *) &cat_arg);
	} else {
		pcap_setnonblock(pcap_hndl, 1, np->errbuf);
		while(!signal_stop) {
			int ret;
			fd_set sel;

			if(np->dev && np->dhcp_active) {
				dhcpc_offers(pcap_hndl, np->dev);
			}
			if(np->wifidev) {
				ret = wifi_scan(np->score_fnc, start_time);
			} else {
				ret = 0;
			}
			if(ret < 0) {
				np->err = ret;
				return 6;
			}
			if(ret < 200) {
				ret = 200;
			}
			time.tv_sec = 0;
			time.tv_usec = ret * 1000;

			FD_ZERO(&sel);
			FD_SET(*((int *)(pcap_hndl)), &sel);
			ret = select(*((int *)(pcap_hndl)) + 1, &sel, NULL, NULL, &time);
			if(ret > 0) {
				ret = pcap_dispatch(pcap_hndl, -1, catcher, (u_char *) &cat_arg);
				if(ret < 0) {
					np->err = ret;
					return 7;
				}
			}
		}
	}
	return 0;
}
