#ifndef __LIB_INFO_NODE_H__
#define __LIB_INFO_NODE_H__

#include <stdint.h>

unsigned node_set_info(const struct shell_exchange *ex, const uint32_t time, int node_type);
void show_time(const struct info_field *info, unsigned space);
void show_nbns(const struct info_field *info);
unsigned show_dhcps(const struct info_field *info, bool oneline);
unsigned show_stp(const struct info_field *info, bool oneline);
unsigned show_cdp(const struct info_field *info, bool oneline);

#endif
