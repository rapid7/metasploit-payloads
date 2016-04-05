ROOT = ../..

include ../../Makefile.common

VPATH = ../../source/extensions/bf

CFLAGS += -I../../source/extensions/bf

objects = bf.o

ext_server_bf.so: $(objects)
	@echo [LD] $@
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $(objects) -lc -lsupport -lmetsrv_main -o $@

clean:
	rm -f *.o *.so
