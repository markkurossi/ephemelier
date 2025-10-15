SH_SRCS = $(wildcard bin/sh/*.mpcl)
SH_DSRCS = $(wildcard bin/sh/*.dmpcl)
SH_CIRUITS = $(patsubst %.mpcl,%.mpclc,$(SH_SRCS))
SH_STAMPS = $(patsubst %.dmpcl,%.stamp,$(SH_DSRCS))

ALL_TARGETS += $(SH_CIRUITS) $(SH_STAMPS)
CLEANFILES  += $(SH_CIRUITS) $(SH_STAMPS) bin/sh/symtab
