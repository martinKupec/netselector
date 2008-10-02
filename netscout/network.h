
enum {
	IPMISC_EAP,
	IPMISC_NTP,
	IPMISC_ICMP,
	IPMISC_WLCCP,
	IPMISC_LAST
};

void ipmisc_add_new(const uint8_t type, shell *sh);
void net_hndl_arp(const uint8_t *pkt, shell *sh);
void net_hndl_stp(const uint8_t *pkt, shell *sh);
void net_hndl_snap(const uint8_t *pkt, shell *sh);
void net_hndl_ip(const uint8_t *pkt, shell *sh);
void net_hndl_eap(const uint8_t *pkt, shell *sh);
