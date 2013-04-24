#!/bin/sh

ifconfig "$1" "$2" netmask 255.255.255.0
route add default gw "$3"
echo "nameserver $3" > /etc/resolv.conf
