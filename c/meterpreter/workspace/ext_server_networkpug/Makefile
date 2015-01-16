ROOT = ../..

include ../../Makefile.common

VPATH = ../../source/extensions/networkpug

CFLAGS += -I../../source/extensions/networkpug

objects = networkpug.o

ext_server_networkpug.so: $(objects)
	@echo [LD] $@
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $(objects) -lc -lsupport -lmetsrv_main -lpcap -o $@

clean:
	rm -f *.o *.so
