TLSD_SRCS = $(wildcard bin/tlsd/*.mpcl)
TLSD_DSRCS = $(wildcard bin/tlsd/*.dmpcl)
TLSD_CIRUITS = $(patsubst %.mpcl,%.mpclc,$(TLSD_SRCS))
TLSD_STAMPS = $(patsubst %.dmpcl,%.stamp,$(TLSD_DSRCS))

ALL_TARGETS += $(TLSD_CIRUITS) $(TLSD_STAMPS)
CLEANFILES  += $(TLSD_CIRUITS) $(TLSD_STAMPS) bin/tlsd/symtab
