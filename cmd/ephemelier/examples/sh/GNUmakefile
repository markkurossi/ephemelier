
SRCS = $(wildcard *.mpcl)
DSRCS =  $(wildcard *.dmpcl)
CIRUITS = $(patsubst %.mpcl,%.mpclc,$(SRCS))
STAMPS = $(patsubst %.dmpcl,%.stamp,$(DSRCS))

all: $(CIRUITS) $(STAMPS)

clean:
	rm -f $(CIRUITS) $(STAMPS)

%.mpclc : %.mpcl
	garbled -sids symtab -pkgpath ../../../../pkg -circ $+

%.stamp : %.dmpcl
	garbled -sids symtab -pkgpath ../../../../pkg -circ -suffix stamp -i 0,0,0,0,0 -pi 0,0,0 $+
