# PKS, I suck at Makefile's.  Given that this compiles POSIX meterpreter and
# associated stuff (openssl, libpcap, etc) this is going to get very messy,
# very quickly.

objects  = source/bionic/compiled/libc.so
objects += source/bionic/compiled/libm.so
objects += source/bionic/compiled/libdl.so
objects += source/bionic/compiled/libcrypto.so
objects += source/bionic/compiled/libssl.so
objects += source/bionic/compiled/libsupport.so
objects += source/bionic/compiled/libmetsrv_main.so
objects += source/bionic/compiled/libpcap.so
objects += data/meterpreter/msflinker_linux_x86.bin
objects += data/meterpreter/ext_server_stdapi.lso
objects += data/meterpreter/ext_server_sniffer.lso
objects += data/meterpreter/ext_server_networkpug.lso

BIONIC=$(PWD)/source/bionic
LIBC=$(BIONIC)/libc
LIBM=$(BIONIC)/libm
COMPILED=$(BIONIC)/compiled

PCAP_CFLAGS = -march=i386 -m32 -Wl,--hash-style=sysv -fno-stack-protector -nostdinc -nostdlib -fPIC -DPIC -g -Wall -D_UNIX -D__linux__  -I$(LIBC)/include -I$(LIBC)/kernel/common/linux/ -I$(LIBC)/kernel/common/ -I$(LIBC)/arch-x86/include/ -I$(LIBC)/kernel/arch-x86/ -Dwchar_t="char" -fno-builtin -D_SIZE_T_DECLARED -DElf_Size="u_int32_t" -D_BYTE_ORDER=_LITTLE_ENDIAN -lgcc -L$(COMPILED) -fPIC -Os -lc

OSSL_CFLAGS=-Os -Wl,--hash-style=sysv -march=i386 -m32 -nostdinc -nostdlib -fno-builtin -fpic -I $(LIBC)/include -I $(LIBC)/kernel/common/linux/ -I $(LIBC)/kernel/common/ -I $(LIBC)/arch-x86/include/ -I $(LIBC)/kernel/arch-x86/  -I$(LIBC)/private -I$(LIBM)/include -DPIC -Dwchar_t='char' -D_SIZE_T_DECLARED -DElf_Size='u_int32_t' -D_BYTE_ORDER=_LITTLE_ENDIAN -L$(COMPILED) -lc

workspace = workspace

all: $(objects)

debug: DEBUG=true
# I'm 99% sure this is the wrong way to do this
debug: MAKE += debug
debug: all

source/bionic/compiled/libc.so: source/bionic/compiled
	(cd source/bionic/libc && ARCH=x86 TOP=${PWD} jam && cd out/x86/ && sh make.sh && [ -f libbionic.so ] )
	cp source/bionic/libc/out/x86/libbionic.so source/bionic/compiled/libc.so

source/bionic/compiled:
	mkdir source/bionic/compiled/

source/bionic/compiled/libm.so:
	$(MAKE) -C $(LIBM) -f msfMakefile && [ -f $(LIBM)/libm.so ]
	cp $(LIBM)/libm.so $(COMPILED)/libm.so

source/bionic/compiled/libdl.so:
	$(MAKE) -C $(BIONIC)/libdl && [ -f $(BIONIC)/libdl/libdl.so ]
	cp $(BIONIC)/libdl/libdl.so $(COMPILED)/libdl.so

source/bionic/compiled/libcrypto.so: tmp/openssl-0.9.8o/libssl.so
	cp tmp/openssl-0.9.8o/libcrypto.so source/bionic/compiled/libcrypto.so

source/bionic/compiled/libssl.so: tmp/openssl-0.9.8o/libssl.so
	cp tmp/openssl-0.9.8o/libssl.so source/bionic/compiled/libssl.so

tmp/openssl-0.9.8o/libssl.so:
	[ -d tmp ] || mkdir tmp
	[ -d tmp/openssl-0.9.8o ] || wget -O tmp/openssl-0.9.8o.tar.gz http://openssl.org/source/openssl-0.9.8o.tar.gz
	[ -f tmp/openssl-0.9.8o/Configure ] || tar -C tmp/ -xzf tmp/openssl-0.9.8o.tar.gz
	(cd tmp/openssl-0.9.8o &&                                                       \
		cat Configure | grep -v 'linux-msf' | \
		sed -e 's#my %table=(#my %table=(     \
			"linux-msf", "gcc:$(OSSL_CFLAGS) -DL_ENDIAN -DTERMIO -Wall::$(OSSL_CFLAGS) -D_REENTRANT::$(OSSL_CFLAGS) -ldl:BN_LLONG $${x86_gcc_des} $${x86_gcc_opts}:$${x86_elf_asm}:dlfcn:linux-shared:$(OSSL_CFLAGS) -fPIC::.so.\\$$\\$$(SHLIB_MAJOR).\\$$\\$$(SHLIB_MINOR)",\
		#;' > Configure-msf;\
		cp Configure-msf Configure && chmod +x Configure && \
		grep linux-msf Configure && \
		./Configure --prefix=/tmp/out threads shared no-hw no-dlfcn no-zlib no-krb5 no-idea 386 linux-msf \
	)
	(cd tmp/openssl-0.9.8o && make depend all ; [ -f libssl.so.0.9.8 -a -f libcrypto.so.0.9.8 ] )
	mkdir -p source/openssl/lib/linux/i386/
	cp tmp/openssl-0.9.8o/libssl.so* tmp/openssl-0.9.8o/libcrypto.so* source/openssl/lib/linux/i386/

source/bionic/compiled/libpcap.so: tmp/libpcap-1.1.1/libpcap.so.1.1.1
	cp tmp/libpcap-1.1.1/libpcap.so.1.1.1 source/bionic/compiled/libpcap.so

tmp/libpcap-1.1.1/libpcap.so.1.1.1:
	[ -d tmp ] || mkdir tmp
	[ -f tmp/libpcap-1.1.1.tar.gz ] || wget -O tmp/libpcap-1.1.1.tar.gz http://www.tcpdump.org/release/libpcap-1.1.1.tar.gz
	[ -f tmp/libpcap-1.1.1/configure  ] || tar -C tmp -xzf tmp/libpcap-1.1.1.tar.gz
	(cd tmp/libpcap-1.1.1 && ./configure --disable-bluetooth --without-bluetooth --without-usb --disable-usb --without-can --disable-can --without-usb-linux --disable-usb-linux --without-libnl)
	echo '#undef HAVE_DECL_ETHER_HOSTTON' >> tmp/libpcap-1.1.1/config.h
	echo '#undef HAVE_SYS_BITYPES_H' >> tmp/libpcap-1.1.1/config.h
	echo '#undef PCAP_SUPPORT_CAN' >> tmp/libpcap-1.1.1/config.h
	echo '#undef PCAP_SUPPORT_USB' >> tmp/libpcap-1.1.1/config.h
	echo '#undef HAVE_ETHER_HOSTTON'  >> tmp/libpcap-1.1.1/config.h
	echo '#define _STDLIB_H this_works_around_malloc_definition_in_grammar_dot_c' >> tmp/libpcap-1.1.1/config.h
	(cd tmp/libpcap-1.1.1 && patch --dry-run -p0 < ../../source/libpcap/pcap_nametoaddr_fix.diff && patch -p0 < ../../source/libpcap/pcap_nametoaddr_fix.diff)
	sed -i -e s/pcap-usb-linux.c//g -e s/fad-getad.c/fad-gifc.c/g tmp/libpcap-1.1.1/Makefile
	sed -i -e s^"CC = gcc"^"CC = gcc $(PCAP_CFLAGS)"^g tmp/libpcap-1.1.1/Makefile
	make -C tmp/libpcap-1.1.1


data/meterpreter/msflinker_linux_x86.bin: source/server/rtld/msflinker.bin
	cp source/server/rtld/msflinker.bin data/meterpreter/msflinker_linux_x86.bin

source/server/rtld/msflinker.bin: source/bionic/compiled/libc.so
	$(MAKE) -C source/server/rtld

$(workspace)/metsrv/libmetsrv_main.so:
	$(MAKE) -C $(workspace)/metsrv

source/bionic/compiled/libmetsrv_main.so: $(workspace)/metsrv/libmetsrv_main.so
	cp $(workspace)/metsrv/libmetsrv_main.so source/bionic/compiled/libmetsrv_main.so

$(workspace)/common/libsupport.so:
	$(MAKE) -C $(workspace)/common

source/bionic/compiled/libsupport.so: $(workspace)/common/libsupport.so
	cp $(workspace)/common/libsupport.so source/bionic/compiled/libsupport.so

$(workspace)/ext_server_sniffer/ext_server_sniffer.so:
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



clean:
	rm -f $(objects)
	(cd source/server/rtld/ && make clean)
	(cd $(workspace) && make clean)

depclean:
	rm -f source/bionic/lib*/*.o
	find source/bionic/ -name '*.a' -print0 | xargs -0 rm -f 2>/dev/null
	rm -f source/bionic/lib*/*.so

clean-pcap:
	#(cd tmp/libpcap-1.1.1/ && make clean)
	# This avoids the pcap target trying to patch the same file more than once.
	# It's a pretty small tar, so untar'ing goes pretty quickly anyway, in
	# contrast to openssl.
	rm -r tmp/libpcap-1.1.1 || true

clean-ssl:
	(cd tmp/openssl-0.9.8o/ && make clean)

really-clean: clean clean-ssl clean-pcap depclean


.PHONY: clean clean-ssl clean-pcap really-clean debug

