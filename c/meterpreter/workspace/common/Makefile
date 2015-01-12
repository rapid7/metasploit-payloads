ROOT = ../..

include $(ROOT)/Makefile.common

VPATH =  $(ROOT)/source/common:
VPATH += $(ROOT)/source/common/crypto:
VPATH += $(ROOT)/source/common/arch/posix:
VPATH += $(ROOT)/source/common/zlib

objects = args.o base.o unix_socket_server.o passfd_server.o ptrace.o \
          base_inject.o base_dispatch.o base_dispatch_common.o buffer.o \
          channel.o common.o core.o list.o remote.o thread.o xor.o zlib.o

libsupport.so: $(objects) Makefile
	@echo [LD] $@
	@$(CC) $(CFLAGS) $(LDFLAGS) -shared $(objects) -lc -lssl -lcrypto -o $@

clean:
	$(RM) -f *.o *.a *.so *.a
