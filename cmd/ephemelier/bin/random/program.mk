RANDOM_SRCS = $(wildcard bin/random/*.mpcl)
RANDOM_DSRCS = $(wildcard bin/random/*.dmpcl)
RANDOM_CIRUITS = $(patsubst %.mpcl,%.mpclc,$(RANDOM_SRCS))
RANDOM_STAMPS = $(patsubst %.dmpcl,%.stamp,$(RANDOM_DSRCS))

ALL_TARGETS += $(RANDOM_CIRUITS) $(RANDOM_STAMPS)
CLEANFILES  += $(RANDOM_CIRUITS) $(RANDOM_STAMPS) bin/random/symtab
