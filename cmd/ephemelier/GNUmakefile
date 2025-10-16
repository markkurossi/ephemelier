
MPCLCFLAGS := -pkgpath ../../pkg -circ -Wnone

# If we were invoked from a subdirectory, compute the subdir prefix.
ifeq ($(subdir),)
# No, we were invoked from the top-level.
subdir_prefix :=
else
# Yes, invoked from a subdirectory.
subdir_prefix := $(subst $(CURDIR)/,,$(subdir))/
endif

PROGRAMS := bin/hello bin/fibo bin/ping bin/pingd bin/sh

# The all target.
all: all-targets

# Include the description of each program.
-include $(patsubst %,%/program.mk,$(PROGRAMS))

all-targets: $(ALL_TARGETS)

clean:
	$(RM) $(filter $(subdir_prefix)%,$(CLEANFILES))

%.mpclc : %.mpcl
	garbled $(MPCLCFLAGS) -sids $(dir $+)symtab $+

%.stamp : %.dmpcl
	garbled $(MPCLCFLAGS) -sids $(dir $+)symtab -suffix stamp -i 0,16x00,44x00,60x00,0 -pi 0,16x00,16x00 $+
