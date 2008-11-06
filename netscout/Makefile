DIRS += netscout
PROGS += obj/netscout/netscout
NSC_OBJS := netscout.o statistics.o

obj/netscout/netscout: $(addprefix obj/netscout/,$(NSC_OBJS)) $(NETLIB)
obj/netscout/netscout: LIBS+=-lpcap -liw
