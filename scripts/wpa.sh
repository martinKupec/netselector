#!/bin/sh
echo $ACTION
if [ "$ACTION" = "UP" ]; then
	echo "Brinking WPA UP"
	wpa_supplicant -B -i $1 -c /etc/wpa_supplicant/wpa_supplicant.conf -Dwext
else
	killall -9 wpa_supplicant
	echo "WPA down"
fi
