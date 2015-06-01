ROOT = ../..

include $(ROOT)/Makefile.common

VPATH += $(ROOT)/source/extensions/sniffer

CFLAGS += -I$(ROOT)/source/extensions/networkpug
CFLAGS += -I.

objects = sniffer.o

ext_server_sniffer.so: $(objects)
	@echo [LD] $@
	@$(CC) $(CFLAGS) $(LDFLAGS) -shared $(objects) -lpcap -lssl -lc -lsupport -lmetsrv_main -o $@

clean:
	rm -f *.o *.so
