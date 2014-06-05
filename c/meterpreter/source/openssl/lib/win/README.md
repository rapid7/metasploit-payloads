# Build instructions for libeay32.lib and ssleay32.lib

These are the instructions for building static DLLs for OpenSSL for
Windows. The procedure here assumes **0.9.8za**, released June 5, 2014.
If this is not the correct version, it should be straightforward enough
to replace all references **za** with whatever is current.

## Preparing the build environment

On a 64-bit build machine (Windows 7 64-bit will do nicely):

- Download openssl from https://openssl.org
- Download ActiveState ActivePerl
- Install ActivePerl
- Download 7zip
- Install 7zip
- Download Visual Studio per Meterpreter instructions
- Install Visiual Studio Express. Takes many clicks.
- Extract source to C:\openssl-0.9.8za (whatever the correct version is)
- Create C:\openssl-0.9.8za-bin
- Create C:\openssl-0.9.8za-bin-64

- Open a Developer Command Prompt for VS2013 (from the Start menu)

## Compiling 32-Bit Binaries

- Get to the source directory:

````
cd C:\openssl-0.9.8za
````

- Start off with a clean slate:

````
  rmdir /s /q out32
  nmake -f ms\nt.mak clean
````

- Configure for a Win32 build target and installation directory.

````
  perl Configure VC-WIN32 no-asm --prefix=C:\openssl-0.9.8za-bin
  ms\do_ms
````

- Don't treat warnings as errors (because there are warnings). Edit
  `ms\nt.mak` `CFLAGS` with notepad, replacing `/W3 /WX` with `/W3 /WX-`
(Hopefully, this step will not be required in future versions of
OpenSSL).

- Compile:

````
  nmake -f ms\nt.mak
````

Test your results.

````
  nmake -f ms\nt.mak test
````

- See the "passed all tests" statement. Yay.

- Copy to the named install directory:

- nmake -f ms\nt.mak install

Now your libs are in openssl-0.9.8za-bin\lib . Hooray!

## Compiling 64-Bit binaries

The process is quite similar.

````
cd C:/openssl-0.9.8za
rmdir /s /q out32
nmake -f ms\nt.mak clean
perl Configure VC-WIN64A no-asm --prefix=C:\openssl-0.9.8za-bin-64
ms\do_win64a
nmake -f ms\nt.mak
nmake -f ms\nt.mak test
nmake -f ms\nt.mak install
````

## Updating Meterpeter source

Copy the resulting binaries (easiest if your build environment is a
Windows VM and your git checkout is either the host OS or another VM on
the same host). They should end up in:

https://github.com/rapid7/meterpreter/tree/master/source/openssl/lib/win

and

https://github.com/rapid7/meterpreter/tree/master/source/openssl/lib/win/x64

## Build Meterpreter

Follow the instructions at:

https://github.com/rapid7/meterpreter/blob/master/README.md

## You're done!



