#ifndef __LIB_WIFI_H__
#define __LIB_WIFI_H__

#include <stdint.h>
#include "lib/netselector.h"

int wifi_init(char *dev, score_callback score_fnc);
void wifi_deinit(void);

#endif

