HELLO_SRCS = $(wildcard bin/hello/*.mpcl)
HELLO_DSRCS = $(wildcard bin/hello/*.dmpcl)
HELLO_CIRUITS = $(patsubst %.mpcl,%.mpclc,$(HELLO_SRCS))
HELLO_STAMPS = $(patsubst %.dmpcl,%.stamp,$(HELLO_DSRCS))

ALL_TARGETS += $(HELLO_CIRUITS) $(HELLO_STAMPS)
CLEANFILES  += $(HELLO_CIRUITS) $(HELLO_STAMPS) bin/hello/symtab
