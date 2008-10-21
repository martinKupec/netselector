.PHONY: all clean dirs
all: dirs netsummoner

C_FILES := $(shell find -iname '*.c' | sort | sed -e 's/^\.\///')
H_FILES := $(shell find -iname '*.h' | sort | sed -e 's/^\.\///')
LEX_FILES := $(shell find -iname '*.lex' | sort | sed -e 's/^\.\///')
O_FILES := $(patsubst %.c,.objs/%.o,$(C_FILES)) $(patsubst %.lex,.objs/%.yy.o,$(LEX_FILES))
CFLAGS := -MD -ggdb -Wall
LDFLAGS = -g -lpcap -liw -Wall
D_FILES := $(shell find -iname '*.d' | sort)

-include $(D_FILES)

$(O_FILES): %: Makefile
netsumonner: Makefile

dirs: .objs/.stamp .deps/.stamp

.%/.stamp: $(C_FILES)
	mkdir -p $(shell echo $(C_FILES) | xargs -n1 -r dirname | uniq | sed -e 's/^/$(patsubst %/.stamp,%,$@)\//')
	touch $@

.objs/%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@ -MF $(patsubst .objs%.o,.deps%.d,$@)

%.yy.c: %.lex
	flex -o $@ --header-file=$(patsubst %.c,%.h,$@) $<

netsummoner: $(O_FILES)
	$(CC) $(LDFLAGS) $(O_FILES) -o $@

clean:
	rm -fr .deps .objs core cscope.out netsumonner configuration.yy.c configuration.yy.h

tags: $(C_FILES) $(H_FILES) Makefile
	exuberant-ctags --c++-kinds=+p --fields=+iaS --extra=+q -I $(C_FILES) $(H_FILES) || true

cscope.out: $(C_FILES) $(H_FILES)
	cscope -b $^ || true
