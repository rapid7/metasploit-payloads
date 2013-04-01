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

Meterpreter requires libpcap-1.1.1 and OpenSSL 0.9.8o sources, which it
will download automatically during the build process. If for some
reason, you cannot access the internet during build, you will need to:
 - wget -O posix-meterp-build-tmp/openssl-0.9.8o.tar.gz http://openssl.org/source/openssl-0.9.8o.tar.gz
 - wget -O posix-meterp-build-tmp/libpcap-1.1.1.tar.gz http://www.tcpdump.org/release/libpcap-1.1.1.tar.gz

Note that the 'depclean' and 'really-clean' make targets will *delete*
these files.

Now you should be able to type `make` in the base directory, go make a
sandwich, and come back to a working[1] meterpreter for Linux.

[1] For some value of "working."  Meterpreter in POSIX environments is
not considered stable.  It does stuff, but expect occasional problems.


Building - Windows
==================
You will need installed *in this order*:

1. Visual C++ 2010 Express (VS2010Express1.iso)
2. Visual Studio 2010 SP1 (VS2010SP1dvd1.iso)
3. Windows SDK 7.1 (GRMSDK_EN_DVD.iso or GRMSDKX_EN_DVD.iso, for x64 compiler tools)
4. VC-Compiler-KB2519277.exe (to fix broken x64 compiler tools)

If you see an error like this during build:

  Error: The "ConfigurationGeneral" rule is missing from the project.

Then your x64 compiler tools are broken. Reinstall Visual Studio and
hope for the best.


Now start Visual Studio and open workspace\meterpreter.sln, and build
the solution (F7). If you get errors about the linker being unable to
open kernel32.lib or other standard Windows libraries, the most likely
cause is an incorrectly installed SDK.

If you are not a Rapid7 employee and therefore don't have access to the
PacketSniffer SDK, the ext_server_sniffer project will fail with an
error about being unable to find a header file. This is normal, don't
worry about it.


Testing
=======
There is currently no automated testing for meterpreter.

Once you've made changes and compiled a new .dll or .so, copy the
contents of the output/ directory into your Metasploit Framework's
data/meterpreter/ directory. In POSIX you can do this automatically if
metasploit-framework and meterpreter live in the same place by running
`make install`

If you made any changes to metsrv.dll or msflinker_linux_x86.bin, ensure
that all extensions still load and function properly.

