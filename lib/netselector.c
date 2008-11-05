
struct stat_ip *(* get_node_ip)(const uint32_t ip);
struct stat_ether *(* get_node_ether)(const uint8_t *mac);
struct stat_wifi *(* get_node_wifi)(const uint8_t *mac);

bool show_received;
