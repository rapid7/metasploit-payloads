ROOT = ../..

include $(ROOT)/Makefile.common

VPATH = $(ROOT)/source/extensions/stdapi

CFLAGS+= -I../../source/extensions/stdapi/server

objects = \
	server/fs/dir.o \
	server/fs/file.o \
	server/fs/fs_posix.o \
	server/general.o \
	server/net/config/interface.o \
	server/net/config/route.o \
	server/net/config/arp.o \
	server/net/config/netstat.o \
	server/net/socket/tcp.o \
	server/net/socket/tcp_server.o \
	server/net/socket/udp.o \
	server/stdapi.o \
	server/sys/config/config.o \
	server/sys/process/linux-in-mem-exe.o \
	server/sys/process/process.o \
	server/sys/process/ps.o

ext_server_stdapi.so: output_dirs $(objects)
	@echo [LD] $@
	@$(CC) $(CFLAGS) $(LDFLAGS) -shared $(objects) -lcrypto -lc -lsupport -lmetsrv_main -o $@

output_dirs:
	@mkdir -p server/fs
	@mkdir -p server/net/config
	@mkdir -p server/net/socket
	@mkdir -p server/sys/config
	@mkdir -p server/sys/process

clean:
	@rm -fr server *.so
