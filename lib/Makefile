DIRS += lib
NETLIB := obj/lib/netlib.a
NETLIB_OBJS := $(patsubst %.c,%.o,$(shell find lib/ -iname '*.c' | sort | sed -e 's/^lib\///'))

NETLIB_MY := $(addprefix obj/lib/,$(NETLIB_OBJS))
$(NETLIB): $(addprefix obj/lib/,$(NETLIB_OBJS))
