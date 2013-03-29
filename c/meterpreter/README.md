meterpreter >
=============

This is an experimental repository for Meterpreter source code as a
separate entity from the Metasploit Framework. See the
meterpreter-submodule branch at:
rapid7/metasploit-framework@43f7d88ca7f001be4a7d346ec89a943b78672425


Building - POSIX
================
You will need:
 - A compiler toolchain (build-essential package on Ubuntu)
 - gcc-multilib, if you're building on a 64-bit machine
 - jam
 - wget
 - patience and luck

Meterpreter requires libpcap-1.1.1 and OpenSSL 0.9.8o sources, which it
will download automatically during the build process. If for some
reason, you cannot access the internet during build, you will need to:
 - wget -O posix-meterp-build-tmp/openssl-0.9.8o.tar.gz http://openssl.org/source/openssl-0.9.8o.tar.gz
 - wget -O posix-meterp-build-tmp/libpcap-1.1.1.tar.gz http://www.tcpdump.org/release/libpcap-1.1.1.tar.gz

Note that the 'depclean' and 'really-clean' make targets will *delete*
these files.

Building - Windows
==================
You will need:
 - Visual Studio 2010
 - luck and patience





