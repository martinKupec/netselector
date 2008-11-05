DIRS+=netscout
PROGS+=netscout
C_FILES += $(shell find netscout -iname '*.c' | sort | sed -e 's/^\.\///')
O_FILES += $(patsubst %.c,objs/%.o,$(C_FILES))
H_FILES += $(shell find netscout -iname '*.h' | sort | sed -e 's/^\.\///')
D_FILES += $(shell find netscout -iname '*.d' | sort)

objs/netscout: $(O_FILES) $(LIBSH)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
objs/netscout: LIBS+=-lpcap -liw

