ROOT = ../..

include $(ROOT)/Makefile.common

VPATH += $(ROOT)/source/server/linux/:
VPATH += $(ROOT)/source/common/arch/posix/:
VPATH += $(ROOT)/source/common/:
VPATH += $(ROOT)/source/server/posix/:
VPATH += $(ROOT)/source/server/

CFLAGS += -I$(ROOT)/source/server
CFLAGS += -std=c99

objects = metsrv.o scheduler.o server_setup_posix.o remote_dispatch_common.o
objects += remote_dispatch.o netlink.o

libmetsrv_main.so: $(objects)
	@echo [LD] $@
	@$(CC) $(CFLAGS) $(LDFLAGS) -shared $(objects) -lc -lssl -lcrypto -o $@
	@$(CC) $(CFLAGS) $(LDFLAGS) -shared $(objects) -export-dynamic -lc -lcrypto -lssl -ldl -lsupport -o $@

clean:
	$(RM) -f *.o *.a *.so *.a
