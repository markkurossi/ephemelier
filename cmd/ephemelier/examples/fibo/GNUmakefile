
SRCS = $(wildcard *.mpcl)
DSRCS =  $(wildcard *.dmpcl)
CIRUITS = $(patsubst %.mpcl,%.mpclc,$(SRCS))
STAMPS = $(patsubst %.dmpcl,%.stamp,$(DSRCS))

MPCLCFLAGS := -sids symtab -pkgpath ../../../../pkg -circ -Wnone

all: $(CIRUITS) $(STAMPS)

clean:
	rm -f $(CIRUITS) $(STAMPS)

%.mpclc : %.mpcl
	garbled $(MPCLCFLAGS) $+

%.stamp : %.dmpcl
	garbled $(MPCLCFLAGS) -suffix stamp -i 0,0x0000000000000000000000000000000000000000000000000000000000,0,0x00000000,0 -pi 0,0,0 $+
