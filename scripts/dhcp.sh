#!/bin/sh
if [ "$ACTION" = "UP" ]; then
	echo "Brinking DHCP UP"
	dhclient $1
else
	killall -9 dhclient
	echo "DHCP down"
fi
