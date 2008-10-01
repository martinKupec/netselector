.PHONY: all clean dirs
all: dirs netscout

C_FILES := $(shell find -iname '*.c' | sort | sed -e 's/^\.\///')
H_FILES := $(shell find -iname '*.h' | sort | sed -e 's/^\.\///')
#O_FILES := $(patsubst %.c,.objs/%.o,$(C_FILES))
O_FILES := netscout.o link_ether.o net_ip.o net_arp.o net_stp.o net_snap.o net_eap.o wifi_scan.o statistics.o dhcpc.o
CFLAGS := -MD -ggdb -Wall
LDFLAGS = -g -lpcap -liw -Wall
D_FILES := $(shell find -iname '*.d' | sort)

-include $(D_FILES)

$(O_FILES): %: Makefile
netscout: Makefile

dirs: .objs/.stamp .deps/.stamp

.%/.stamp: $(C_FILES)
	mkdir -p $(shell echo $(C_FILES) | xargs -n1 -r dirname | uniq | sed -e 's/^/$(patsubst %/.stamp,%,$@)\//')
	touch $@

.objs/%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@ -MF $(patsubst .objs%.o,.deps%.d,$@)

netscout: $(O_FILES)
	$(CC) $(LDFLAGS) $(O_FILES) -o $@

clean:
	rm -fr .deps .objs core cscope.out netscout

tags: $(C_FILES) $(H_FILES) Makefile
	exuberant-ctags --c++-kinds=+p --fields=+iaS --extra=+q -I $(C_FILES) $(H_FILES) || true

cscope.out: $(C_FILES) $(H_FILES)
	cscope -b $^ || true
