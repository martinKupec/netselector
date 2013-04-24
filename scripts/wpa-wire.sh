#!/bin/sh
if [ "$ACTION" = "UP" ]; then
	echo "Brinking WPA UP"
	wpa_supplicant -B -i $1 -c /etc/wpa_supplicant/wpa_supplicant.conf.wired -Dwired
else
	killall -9 wpa_supplicant
	echo "WPA down"
fi
