SUBDIRS := perisco

.PHONY: $(SUBDIRS)

$(SUBDIRS):
	make -C $@