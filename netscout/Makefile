CC = gcc

CFLAGS = -g -Wall
LDFLAGS = -g -lpcap -liw -Wall

all: netscout

netscout: netscout.o link_ether.o net_ip.o net_arp.o net_stp.o net_snap.o wifi_scan.o statistics.o

clean:
	rm -rf *.o netscout
