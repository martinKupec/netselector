#!/bin/sh
wpa_supplicant -B -i $1 -c /etc/wpa_supplicant/wpa_supplicant.conf -Dwext
