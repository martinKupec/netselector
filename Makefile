CC=gcc
CLANG=-std=gnu99
COPT=-O2 -fstrict-aliasing -finline-limit=2000
CWARNS=-Wall -W -Wno-parentheses -Wstrict-prototypes -Wmissing-prototypes -Winline
LOPT=
LIBS= 
CDEBUG=-DDEBUG -ggdb

CFLAGS=$(CLANG) $(COPT) $(CDEBUG) $(CWARNS) -I.
LDFLAGS=$(LOPT)

.PHONY: all clean dirs
all: dirs programs

DIRS=
PROGS=
D_FILES=
C_FILES=

include netscout/Makefile
#include lib/Makefile
#include netsummoner/Makefile

-include $(D_FILES)

$(O_FILES): %: Makefile
programs: $(PROGS) Makefile

dirs: objs/.stamp .deps/.stamp

%/.stamp: $(C_FILES)
	mkdir -p $(shell echo $(C_FILES) | xargs -n1 -r dirname | uniq | sed -e 's/^/$(patsubst %/.stamp,%,$@)\//')
	touch $@

objs/%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@ -MM -MF $(patsubst objs%.o,.deps%.d,$@)

clean:
	rm -fr .deps objs core cscope.out

tags: $(C_FILES) $(H_FILES) Makefile
	exuberant-ctags --c++-kinds=+p --fields=+iaS --extra=+q -I `find . -name "*.[ch]"` || true

cscope.out: $(C_FILES) $(H_FILES)
	cscope -b $^ || true

.SECONDARY:
