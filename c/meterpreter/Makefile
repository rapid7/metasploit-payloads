
# Used by 'install' target. Change this to wherever your framework checkout is.
# Doesn't have to be development. Should point to the base directory where
# msfconsole lives.
framework_dir = ../../../metasploit-framework/

# Change me if you want to build openssl and libpcap somewhere else
build_tmp = posix-meterp-build-tmp
cwd=$(shell pwd)

ROOT=$(basename $(CURDIR:%/=%))
BIONIC=$(ROOT)/source/bionic
LIBC=$(BIONIC)/libc
LIBM=$(BIONIC)/libm
COMPILED=$(BIONIC)/compiled

objects  = $(COMPILED)/libc.so
objects += $(COMPILED)/libm.so
objects += $(COMPILED)/libdl.so
objects += $(COMPILED)/libcrypto.so
objects += $(COMPILED)/libssl.so
objects += $(COMPILED)/libsupport.so
objects += $(COMPILED)/libmetsrv_main.so
objects += $(COMPILED)/libpcap.so

outputs  = data/meterpreter/msflinker_linux_x86.bin
outputs += data/meterpreter/ext_server_stdapi.lso
outputs += data/meterpreter/ext_server_sniffer.lso
outputs += data/meterpreter/ext_server_networkpug.lso

STD_CFLAGS =  -Os -m32 -march=i386 -fno-stack-protector
STD_CFLAGS += -Wl,--hash-style=sysv
STD_CFLAGS += -lc -lm -nostdinc -nostdlib -fno-builtin -fPIC -DPIC
STD_CFLAGS += -Dwchar_t='char' -D_SIZE_T_DECLARED -DElf_Size='u_int32_t'
STD_CFLAGS += -D_BYTE_ORDER=_LITTLE_ENDIAN -D_UNIX -D__linux__ -lgcc
STD_CFLAGS += -I$(LIBC)/include
STD_CFLAGS += -I$(LIBC)/kernel/common/linux/
STD_CFLAGS += -I$(LIBC)/kernel/common/
STD_CFLAGS += -I$(LIBC)/arch-x86/include/
STD_CFLAGS += -I$(LIBC)/kernel/arch-x86/
STD_CFLAGS += -L$(COMPILED)

GCCGOLD = $(shell (echo "int main(){}" | gcc -fuse-ld=gold -o/dev/null -xc -); echo $$?)
ifeq "$(GCCGOLD)" "0"
    STD_CFLAGS += -fuse-ld=gold
endif

PCAP_CFLAGS = $(STD_CFLAGS)

OSSL_CFLAGS = $(STD_CFLAGS) -I$(LIBC)/private -I$(LIBM)/include

workspace = workspace

all: $(objects) $(outputs)

include deps/libressl/Makefile
include deps/libpcap/Makefile

debug: DEBUG=true
# I'm 99% sure this is the wrong way to do this
debug: MAKE += debug
debug: all

$(COMPILED):
	mkdir $(COMPILED)/

$(COMPILED)/libc.so: $(COMPILED)
	@echo Building libc
	@(cd source/bionic/libc && ARCH=x86 TOP=${ROOT} jam > build.log 2>&1 )
	@(cd source/bionic/libc/out/x86/ && $(MAKE) -f Makefile.msf >> build.log 2>&1 && [ -f libbionic.so ])
	@cp source/bionic/libc/out/x86/libbionic.so $(COMPILED)/libc.so

$(COMPILED)/libm.so:
	@echo Building libm
	@$(MAKE) -C $(LIBM) -f Makefile.msf > build.log 2>&1 && [ -f $(LIBM)/libm.so ]
	@cp $(LIBM)/libm.so $(COMPILED)/libm.so

$(COMPILED)/libdl.so:
	@echo Building libdl
	@$(MAKE) -C $(BIONIC)/libdl > build.log && [ -f $(BIONIC)/libdl/libdl.so ]
	@cp $(BIONIC)/libdl/libdl.so $(COMPILED)/libdl.so

data/meterpreter/msflinker_linux_x86.bin: source/server/rtld/msflinker.bin
	cp source/server/rtld/msflinker.bin data/meterpreter/msflinker_linux_x86.bin

source/server/rtld/msflinker.bin: $(COMPILED)/libc.so \
	$(wildcard source/server/*.h) \
	$(wildcard source/server/*.c)
	$(MAKE) -C source/server/rtld

$(workspace)/metsrv/libmetsrv_main.so: $(COMPILED)/libsupport.so \
	$(wildcard source/server/*.h) \
	$(wildcard source/server/*.c)
	$(MAKE) -C $(workspace)/metsrv

$(COMPILED)/libmetsrv_main.so: $(workspace)/metsrv/libmetsrv_main.so
	cp $(workspace)/metsrv/libmetsrv_main.so $(COMPILED)/libmetsrv_main.so

$(workspace)/common/libsupport.so: \
	$(wildcard source/common/*.h) \
	$(wildcard source/common/*.c)
	$(MAKE) -C $(workspace)/common

$(COMPILED)/libsupport.so: $(workspace)/common/libsupport.so
	cp $(workspace)/common/libsupport.so $(COMPILED)/libsupport.so

$(workspace)/ext_server_sniffer/ext_server_sniffer.so: \
	$(wildcard source/extensions/sniffer/*.h) \
	$(wildcard source/extensions/sniffer/*.c) \
	$(COMPILED)/libpcap.so
	$(MAKE) -C $(workspace)/ext_server_sniffer

data/meterpreter/ext_server_sniffer.lso: \
	$(workspace)/ext_server_sniffer/ext_server_sniffer.so
	cp $(workspace)/ext_server_sniffer/ext_server_sniffer.so \
		data/meterpreter/ext_server_sniffer.lso

$(workspace)/ext_server_stdapi/ext_server_stdapi.so: \
	$(wildcard source/extensions/stdapi/*.h) \
	$(wildcard source/extensions/stdapi/*.c)
	$(MAKE) -C $(workspace)/ext_server_stdapi

data/meterpreter/ext_server_stdapi.lso: \
	$(workspace)/ext_server_stdapi/ext_server_stdapi.so
	cp $(workspace)/ext_server_stdapi/ext_server_stdapi.so \
		data/meterpreter/ext_server_stdapi.lso

$(workspace)/ext_server_networkpug/ext_server_networkpug.so: \
	$(wildcard source/extensions/networkpug/*.h) \
	$(wildcard source/extensions/networkpug/*.c)
	$(MAKE) -C $(workspace)/ext_server_networkpug

data/meterpreter/ext_server_networkpug.lso: \
    $(workspace)/ext_server_networkpug/ext_server_networkpug.so
	cp $(workspace)/ext_server_networkpug/ext_server_networkpug.so \
		data/meterpreter/ext_server_networkpug.lso


install: $(outputs)
	cp $(outputs) $(framework_dir)/data/meterpreter/

clean:
	rm -f $(objects)
	make -C source/server/rtld/ clean
	make -C $(workspace) clean

depclean:
	rm -f source/bionic/lib*/*.o
	find source/bionic/ -name '*.a' -print0 | xargs -0 rm -f 2>/dev/null
	find source/bionic/ -name '*.so' -print0 | xargs -0 rm -f 2>/dev/null
	find . -name 'build.log' | xargs rm -f
	rm -f source/bionic/lib*/*.so

really-clean: clean clean-ssl clean-pcap depclean

distclean: really-clean

.PHONY: clean clean-ssl clean-pcap really-clean debug

