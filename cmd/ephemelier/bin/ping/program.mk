PING_SRCS = $(wildcard bin/ping/*.mpcl)
PING_DSRCS = $(wildcard bin/ping/*.dmpcl)
PING_CIRUITS = $(patsubst %.mpcl,%.mpclc,$(PING_SRCS))
PING_STAMPS = $(patsubst %.dmpcl,%.stamp,$(PING_DSRCS))

ALL_TARGETS += $(PING_CIRUITS) $(PING_STAMPS)
CLEANFILES  += $(PING_CIRUITS) $(PING_STAMPS) bin/ping/symtab
