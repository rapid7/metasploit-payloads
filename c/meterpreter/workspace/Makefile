SUBDIRS = common metsrv
SUBDIRS += ext_server_stdapi
SUBDIRS += ext_server_sniffer
SUBDIRS += ext_server_networkpug

subdirs:
	for dir in $(SUBDIRS); do \
	$(MAKE) -C $$dir; \
	done

.PHONY:
clean:
	for dir in $(SUBDIRS); do \
	$(MAKE) -C $$dir clean; \
	done
