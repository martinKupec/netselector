CC := gcc
CLANG := -std=gnu99
COPT := -O2 -fstrict-aliasing -finline-limit=2000
CWARNS := -Wall -W -Wno-parentheses -Wstrict-prototypes -Wmissing-prototypes -Winline
LOPT =
LIBS =
CDEBUG := -DDEBUG -ggdb

CFLAGS := $(CLANG) $(COPT) $(CDEBUG) $(CWARNS) -I.
LDFLAGS := $(LOPT)

.PHONY: all dust clean distclean programs dirtree

DIRS =
PROGS =

all: dirtree programs

dust::
	rm -f `find . -path "*~" -or -name "\#*\#" -or -name core`

clean:: dust
	rm -rf obj
	rm -f depend depend.new TAGS

distclean:: clean

include lib/Makefile
include netscout/Makefile

programs: $(PROGS)

dirtree: $(addsuffix /.dir-stamp,$(addprefix obj/,$(DIRS)))

tags:
	etags `find . -name "*.[ch]"`

# Black magic with dependencies. It would be more correct to make "depend.new"
# a prerequisite for "depend", but "depend.new" often has the same timestamp
# as "depend" which would confuse make a lot and either force remaking anyway
# or (as in current versions of GNU make) erroneously skipping the remaking.

-include depend

depend: force
	if [ -s depend.new ] ; then build/mergedeps depend depend.new ; >depend.new ; fi

force:

# Implicit rules

%.a:
	ar rcs $@ $?

%.dir-stamp:
	mkdir -p $(@D) && touch $@

obj/%.o: %.c
	DEPENDENCIES_OUTPUT="depend.new $@" $(CC) $(CFLAGS) -c -o $@ $<

obj/%-tt.o: %.c
	DEPENDENCIES_OUTPUT="depend.new $@" $(CC) $(CFLAGS) -DTEST -c -o $@ $<

obj/%-t: obj/%-tt.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

obj/%: obj/%.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Don't delete intermediate targets. There shouldn't be any, but due to bugs
# in GNU Make rules with targets in not-yet-existing directories are ignored
# when searching for implicit rules and thence targets considered intermediate.
.SECONDARY:
