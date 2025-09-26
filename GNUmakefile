BLOG := ../blog
OUTPUT = ,apidoc

all:
	@echo "Targets: apidoc public"

apidoc:
	$(BLOG)/blog -site -lib $(BLOG) -draft -t templates/mpcl -o $(OUTPUT) docs/apidoc/
	mpcldoc -pkgpath pkg -dir $(OUTPUT) pkg cmd/ephemelier/examples

public:
	make apidoc OUTPUT=$(HOME)/work/www/mpcl
