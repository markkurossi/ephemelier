
SRCS = $(wildcard *.mpcl)
CIRUITS = $(patsubst %.mpcl,%.mpclc,$(SRCS))

all: $(CIRUITS)

clean:
	rm -f $(CIRUITS)

%.mpclc : %.mpcl
	garbled -pkgpath ../../../../pkg -circ $+
