phony_targets = all clean debug

.PHONY : $(phony_targets)
$(phony_targets) :
	@$(MAKE) subdir="$(CURDIR)" -C "$(TOP_SRCDIR)" $@
