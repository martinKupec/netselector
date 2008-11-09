#include <lib/netselector.h>

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
