
SUBDIRS := $(wildcard */.)

all : $(SUBDIRS)

$(SUBDIRS) :
	$(MAKE) -C $@

install clean :
	@for i in $(SUBDIRS); do \
		$(MAKE) -C $${i} $@; \
	done

.PHONY: all
.PHONY: install
.PHONY: clean
.PHONY: $(SUBDIRS)
