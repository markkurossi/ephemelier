phony_targets = all clean debug

.PHONY : $(phony_targets)
$(phony_targets) :
	@echo "make[1]: Entering directory '$(CURDIR)/$(TOP_SRCDIR)'"
	@$(MAKE) subdir="$(CURDIR)" -C "$(TOP_SRCDIR)" $@
