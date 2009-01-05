DIRS += netsummoner
PROGS += obj/netsummoner/netsummoner
LEX_SRC := $(shell find netsummoner/ -iname '*.lex' | sort | sed -e 's/^netsummoner\///')
BISON_SRC := $(shell find netsummoner/ -iname '*.y' | sort | sed -e 's/^netsummoner\///')

NSU_OBJS := $(patsubst %.y,%.tab.o,$(BISON_SRC)) $(patsubst %.lex,%.yy.o,$(LEX_SRC))
NSU_OBJS += $(patsubst %.c,%.o,$(shell find netsummoner/ -iname '*.c' | sort | sed -e 's/^netsummoner\///'))

obj/netsummoner/netsummoner: $(addprefix obj/netsummoner/,$(NSU_OBJS)) $(NETLIB)
obj/netsummoner/netsummoner: LIBS+=-lpcap -liw -lwpa_ctrl -lwpa_common -lwpa_unix
