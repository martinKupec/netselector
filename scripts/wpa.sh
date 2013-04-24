#!/bin/sh
if [ "$ACTION" = "UP" ]; then
	echo "Brinking WPA UP"
	ifconfig eth0 0.0.0.0
	wpa_supplicant -B -i $1 -c /etc/wpa_supplicant/wpa_supplicant.conf -Dwext
else
	killall -9 wpa_supplicant
	echo "WPA down"
fi
