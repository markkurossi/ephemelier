FIBO_SRCS = $(wildcard bin/fibo/*.mpcl)
FIBO_DSRCS = $(wildcard bin/fibo/*.dmpcl)
FIBO_CIRUITS = $(patsubst %.mpcl,%.mpclc,$(FIBO_SRCS))
FIBO_STAMPS = $(patsubst %.dmpcl,%.stamp,$(FIBO_DSRCS))

ALL_TARGETS += $(FIBO_CIRUITS) $(FIBO_STAMPS)
CLEANFILES  += $(FIBO_CIRUITS) $(FIBO_STAMPS) bin/fibo/symtab
