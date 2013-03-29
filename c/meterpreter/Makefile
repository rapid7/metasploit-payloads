

# Used by 'install' target. Change this to wherever your framework checkout is.
# Doesn't have to be development. Should point to the base directory where
# msfconsole lives.
framework_dir = ../metasploit-framework/

# Change me if you want to build openssl and libpcap somewhere else
build_tmp = posix-meterp-build-tmp


BIONIC=$(PWD)/source/bionic
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

#PCAP_CFLAGS = -march=i386 -m32 -Wl,--hash-style=sysv -fno-stack-protector -nostdinc -nostdlib -fPIC -DPIC -g -Wall -D_UNIX -D__linux__  -I$(LIBC)/include -I$(LIBC)/kernel/common/linux/ -I$(LIBC)/kernel/common/ -I$(LIBC)/arch-x86/include/ -I$(LIBC)/kernel/arch-x86/ -Dwchar_t="char" -fno-builtin -D_SIZE_T_DECLARED -DElf_Size="u_int32_t" -D_BYTE_ORDER=_LITTLE_ENDIAN -lgcc -L$(COMPILED) -fPIC -Os -lc
PCAP_CFLAGS = \
 -Os \
 -Wl,--hash-style=sysv \
 -march=i386 \
 -m32 \
 -fno-stack-protector \
 -nostdinc \
 -nostdlib \
 -fno-builtin \
 -fPIC \
 -DPIC \
 -Wall \
 -lc \
 -I$(LIBC)/include \
 -I$(LIBC)/kernel/common/linux/ \
 -I$(LIBC)/kernel/common/ \
 -I$(LIBC)/arch-x86/include/ \
 -I$(LIBC)/kernel/arch-x86/ \
 -L$(COMPILED) \
 -Dwchar_t="char" \
 -D_SIZE_T_DECLARED \
 -DElf_Size="u_int32_t" \
 -D_BYTE_ORDER=_LITTLE_ENDIAN \
 -D_UNIX \
 -D__linux__ \
 -lgcc

#OSSL_CFLAGS = -Os -Wl,--hash-style=sysv -march=i386 -m32 -nostdinc -nostdlib -fno-builtin -fpic -I $(LIBC)/include -I $(LIBC)/kernel/common/linux/ -I $(LIBC)/kernel/common/ -I $(LIBC)/arch-x86/include/ -I $(LIBC)/kernel/arch-x86/  -I$(LIBC)/private -I$(LIBM)/include -DPIC -Dwchar_t='char' -D_SIZE_T_DECLARED -DElf_Size='u_int32_t' -D_BYTE_ORDER=_LITTLE_ENDIAN -L$(COMPILED) -lc
OSSL_CFLAGS = \
 -Os \
 -Wl,--hash-style=sysv \
 -march=i386 \
 -m32 \
 -nostdinc \
 -nostdlib \
 -fno-builtin \
 -fpic \
 -DPIC \
 -lc \
 -I $(LIBC)/include \
 -I $(LIBC)/kernel/common/linux/ \
 -I $(LIBC)/kernel/common/ \
 -I $(LIBC)/arch-x86/include/ \
 -I $(LIBC)/kernel/arch-x86/ \
 -I$(LIBC)/private \
 -I$(LIBM)/include \
 -L$(COMPILED) \
 -Dwchar_t='char' \
 -D_SIZE_T_DECLARED \
 -DElf_Size='u_int32_t' \
 -D_BYTE_ORDER=_LITTLE_ENDIAN \

workspace = workspace

all: $(objects) $(outputs)

debug: DEBUG=true
# I'm 99% sure this is the wrong way to do this
debug: MAKE += debug
debug: all

$(COMPILED):
	mkdir $(COMPILED)/

$(COMPILED)/libc.so: $(COMPILED)
	(cd source/bionic/libc && ARCH=x86 TOP=${PWD} jam)
	(cd source/bionic/libc/out/x86/ && $(MAKE) -f Makefile.msf && [ -f libbionic.so ])
	cp source/bionic/libc/out/x86/libbionic.so $(COMPILED)/libc.so

$(COMPILED)/libm.so:
	$(MAKE) -C $(LIBM) -f Makefile.msf && [ -f $(LIBM)/libm.so ]
	cp $(LIBM)/libm.so $(COMPILED)/libm.so

$(COMPILED)/libdl.so:
	$(MAKE) -C $(BIONIC)/libdl && [ -f $(BIONIC)/libdl/libdl.so ]
	cp $(BIONIC)/libdl/libdl.so $(COMPILED)/libdl.so

$(COMPILED)/libcrypto.so: $(build_tmp)/openssl-0.9.8o/libssl.so
	cp $(build_tmp)/openssl-0.9.8o/libcrypto.so source/bionic/compiled/libcrypto.so

$(COMPILED)/libssl.so: $(build_tmp)/openssl-0.9.8o/libssl.so
	cp $(build_tmp)/openssl-0.9.8o/libssl.so source/bionic/compiled/libssl.so

$(build_tmp)/openssl-0.9.8o/libssl.so:
	[ -d $(build_tmp) ] || mkdir $(build_tmp)
	[ -f $(build_tmp)/openssl-0.9.8o.tar.gz ] || wget -O $(build_tmp)/openssl-0.9.8o.tar.gz http://openssl.org/source/openssl-0.9.8o.tar.gz
	[ -d $(build_tmp)/openssl-0.9.8o ] || tar -C $(build_tmp)/ -xzf $(build_tmp)/openssl-0.9.8o.tar.gz
	(cd $(build_tmp)/openssl-0.9.8o &&                                                       \
		cat Configure | grep -v 'linux-msf' | \
		sed -e 's#my %table=(#my %table=(     \
			"linux-msf", "gcc:$(OSSL_CFLAGS) -DL_ENDIAN -DTERMIO -Wall::-D_REENTRANT::$(OSSL_CFLAGS) -ldl:BN_LLONG $${x86_gcc_des} $${x86_gcc_opts}:$${x86_elf_asm}:dlfcn:linux-shared:$(OSSL_CFLAGS) -fPIC::.so.\\$$\\$$(SHLIB_MAJOR).\\$$\\$$(SHLIB_MINOR)",\
		#;' > Configure-msf;\
		cp Configure-msf Configure && chmod +x Configure && \
		grep linux-msf Configure && \
		./Configure --prefix=/tmp/out threads shared no-hw no-dlfcn no-zlib no-krb5 no-idea 386 linux-msf \
	)
	(cd $(build_tmp)/openssl-0.9.8o && $(MAKE) depend all ; [ -f libssl.so.0.9.8 -a -f libcrypto.so.0.9.8 ] )

$(COMPILED)/libpcap.so: $(build_tmp)/libpcap-1.1.1/libpcap.so.1.1.1
	cp $(build_tmp)/libpcap-1.1.1/libpcap.so.1.1.1 $(COMPILED)/libpcap.so

$(build_tmp)/libpcap-1.1.1/libpcap.so.1.1.1:
	[ -d $(build_tmp) ] || mkdir $(build_tmp)
	[ -f $(build_tmp)/libpcap-1.1.1.tar.gz ] || wget -O $(build_tmp)/libpcap-1.1.1.tar.gz http://www.tcpdump.org/release/libpcap-1.1.1.tar.gz
	[ -f $(build_tmp)/libpcap-1.1.1/configure ] || tar -C $(build_tmp) -xzf $(build_tmp)/libpcap-1.1.1.tar.gz
	(cd $(build_tmp)/libpcap-1.1.1 && ./configure --disable-bluetooth --without-bluetooth --without-usb --disable-usb --without-can --disable-can --without-usb-linux --disable-usb-linux --without-libnl)
	echo '#undef HAVE_DECL_ETHER_HOSTTON' >> $(build_tmp)/libpcap-1.1.1/config.h
	echo '#undef HAVE_SYS_BITYPES_H' >> $(build_tmp)/libpcap-1.1.1/config.h
	echo '#undef PCAP_SUPPORT_CAN' >> $(build_tmp)/libpcap-1.1.1/config.h
	echo '#undef PCAP_SUPPORT_USB' >> $(build_tmp)/libpcap-1.1.1/config.h
	echo '#undef HAVE_ETHER_HOSTTON'  >> $(build_tmp)/libpcap-1.1.1/config.h
	echo '#define _STDLIB_H this_works_around_malloc_definition_in_grammar_dot_c' >> $(build_tmp)/libpcap-1.1.1/config.h
	(cd $(build_tmp)/libpcap-1.1.1 && patch --dry-run -p0 < ../../source/libpcap/pcap_nametoaddr_fix.diff && patch -p0 < ../../source/libpcap/pcap_nametoaddr_fix.diff)
	sed -i -e s/pcap-usb-linux.c//g -e s/fad-getad.c/fad-gifc.c/g $(build_tmp)/libpcap-1.1.1/Makefile
	sed -i -e s^"CC = gcc"^"CC = gcc $(PCAP_CFLAGS)"^g $(build_tmp)/libpcap-1.1.1/Makefile
	$(MAKE) -C $(build_tmp)/libpcap-1.1.1


data/meterpreter/msflinker_linux_x86.bin: source/server/rtld/msflinker.bin
	cp source/server/rtld/msflinker.bin data/meterpreter/msflinker_linux_x86.bin

source/server/rtld/msflinker.bin: $(COMPILED)/libc.so
	$(MAKE) -C source/server/rtld

$(workspace)/metsrv/libmetsrv_main.so: $(COMPILED)/libsupport.so
	$(MAKE) -C $(workspace)/metsrv

$(COMPILED)/libmetsrv_main.so: $(workspace)/metsrv/libmetsrv_main.so
	cp $(workspace)/metsrv/libmetsrv_main.so $(COMPILED)/libmetsrv_main.so

$(workspace)/common/libsupport.so:
	$(MAKE) -C $(workspace)/common

$(COMPILED)/libsupport.so: $(workspace)/common/libsupport.so
	cp $(workspace)/common/libsupport.so $(COMPILED)/libsupport.so

$(workspace)/ext_server_sniffer/ext_server_sniffer.so: $(COMPILED)/libpcap.so
	$(MAKE) -C $(workspace)/ext_server_sniffer

data/meterpreter/ext_server_sniffer.lso: $(workspace)/ext_server_sniffer/ext_server_sniffer.so
	cp $(workspace)/ext_server_sniffer/ext_server_sniffer.so data/meterpreter/ext_server_sniffer.lso

$(workspace)/ext_server_stdapi/ext_server_stdapi.so:
	$(MAKE) -C $(workspace)/ext_server_stdapi

data/meterpreter/ext_server_stdapi.lso: $(workspace)/ext_server_stdapi/ext_server_stdapi.so
	cp $(workspace)/ext_server_stdapi/ext_server_stdapi.so data/meterpreter/ext_server_stdapi.lso

$(workspace)/ext_server_networkpug/ext_server_networkpug.so:
	$(MAKE) -C $(workspace)/ext_server_networkpug

data/meterpreter/ext_server_networkpug.lso: $(workspace)/ext_server_networkpug/ext_server_networkpug.so
	cp $(workspace)/ext_server_networkpug/ext_server_networkpug.so data/meterpreter/ext_server_networkpug.lso


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
	rm -f source/bionic/lib*/*.so
	rm -rf source/openssl/lib/linux/i386/
	rm -rf $(build_tmp)

clean-pcap:
	#(cd $(build_tmp)/libpcap-1.1.1/ && make clean)
	# This avoids the pcap target trying to patch the same file more than once.
	# It's a pretty small tar, so untar'ing goes pretty quickly anyway, in
	# contrast to openssl.
	rm -r $(build_tmp)/libpcap-1.1.1 || true

clean-ssl:
	make -C $(build_tmp)/openssl-0.9.8o/ clean

really-clean: clean clean-ssl clean-pcap depclean


.PHONY: clean clean-ssl clean-pcap really-clean debug

