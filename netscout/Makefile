CC = gcc

CFLAGS = -g -Wall
LDFLAGS = -lpcap

all: netscout

netscout: netscout.o link_ether.o net_ip.o net_arp.o net_stp.o net_snap.o

clean:
	rm -rf *.o netscout
