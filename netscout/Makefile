CC = gcc

CFLAGS = -g -Wall
LDFLAGS = -g -lpcap -liw -Wall

all: netscout

netscout: netscout.o link_ether.o net_ip.o net_arp.o net_stp.o net_snap.o net_eap.o wifi_scan.o statistics.o dhcpc.o

clean:
	rm -rf *.o netscout
