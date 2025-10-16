PINGD_SRCS = $(wildcard bin/pingd/*.mpcl)
PINGD_DSRCS = $(wildcard bin/pingd/*.dmpcl)
PINGD_CIRUITS = $(patsubst %.mpcl,%.mpclc,$(PINGD_SRCS))
PINGD_STAMPS = $(patsubst %.dmpcl,%.stamp,$(PINGD_DSRCS))

ALL_TARGETS += $(PINGD_CIRUITS) $(PINGD_STAMPS)
CLEANFILES  += $(PINGD_CIRUITS) $(PINGD_STAMPS) bin/pingd/symtab
