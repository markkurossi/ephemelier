CAT_SRCS = $(wildcard bin/cat/*.mpcl)
CAT_DSRCS = $(wildcard bin/cat/*.dmpcl)
CAT_CIRUITS = $(patsubst %.mpcl,%.mpclc,$(CAT_SRCS))
CAT_STAMPS = $(patsubst %.dmpcl,%.stamp,$(CAT_DSRCS))

ALL_TARGETS += $(CAT_CIRUITS) $(CAT_STAMPS)
CLEANFILES  += $(CAT_CIRUITS) $(CAT_STAMPS) bin/cat/symtab
