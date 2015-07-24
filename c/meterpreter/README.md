Native C meterpreter >
=============

Building - Windows
==================

As of [commit
a2888b1b4862819c9aae81bf46d8c92d8164c598](https://github.com/rapid7/meterpreter/commit/a2888b1b4862819c9aae81bf46d8c92d8164c598),
Meterpreter is built with [Visual Studio 2013 Express for
Desktop][vs_express] or any paid version of [Visual Studio
2013][vs_paid]. Earlier toolsets on Windows are no longer supported --
this includes Visual Studio 2012.  Make sure that the version that you
download is `Visual Studio Express 2013 for Windows Desktop` -- dependng
on your operating system, if you get the wrong version of VS2013, the
installer will complain about needing "a more recent version of
Windows." If you are using a dedicated build machine, your best bet is
to uninstall Visual Studio 2012 if your only project is Meterpreter.

Visual Studio 2013 requires .NET 4.5.1 in order to run, and as a result isn't compatible
with Windows XP due to the fact that .NET 4.5 will not run on Windows XP. However, this
does not mean that Metepreter itself will not run on Windows XP, it just means that it's
not possible to _build_ it on Windows XP.

Windows Meterpreter has the following repositories set up as submodule dependencies:

* [Reflective DLL Injection][rdi]

For Meterpreter to build correctly, these submodules must be initialised and updated,
like so:

``` bash
$ git clone https://github.com/rapid7/meterpreter
$ cd meterpreter
$ git submodule init && git submodule update
```

At this point the dependencies will be ready to use and Meterpreter should be ready to
build.

* [OpenSSL][openssl]

Occasionally, new versions of OpenSSL are released and need to be
incorporated into the Meterpreter build. See the README under
`source/openssl/lib` for build instructions. You will also need to
refresh the header files from the source tarball as well. TODO: This
entire process appears automatable given a proper build environment.

An example of updating OpenSSL is detailed in
[Pull Request #86](https://github.com/rapid7/meterpreter/pull/86).

Running the Build
-----------------

Open up a Visual Studio command prompt by selecting `Developer Command Prompt for VS2013`
from the Start menu. Alternatively you can run `vcvars32.bat` from an existing command
line prompt, just make sure it's the VS2013 one if you have multiple versions of VS
installed on your machine.

Once you have your environment variables set up, change to the root folder where the
meterpreter source is located. From here you can:

* Build the x86 version by running: `make x86`
* Build the x64 version by running: `make x64`
* Build both x86 and x64 versions by running: `make`

The compiled binaries are written to the `output/x86` and `output/x64` folders.

If you are not a Rapid7 employee, make sure you build the source using the `debug` or
`release` configurations when inside Visual Studio. If you attempt to build `r7_debug` or
`r7_release` you will get compiler errors due to missing libraries.

If you build the source from the command line the toolset will choose the most
appropriate build configuration for you and hence calling `make` should "Just Work&trade;".

If you are a Rapid7 employee you will need the PSSDK source in order to build the
extra components using the `r7_*` build configurations.

If submodule dependencies are not found on the file system, the script should display
an error message like so:

```
Meterpreter's submodule dependencies can't be found.
From your git console, please run:
  $ git submodule init && git submodule update
```

Building - POSIX
================
You will need:
 - A compiler toolchain (build-essential package on Ubuntu)
 - gcc-multilib, if you're building on a 64-bit machine
 - jam
 - wget
 - flex

On Ubuntu 14.04:
  apt-get install gcc jam make flex bison gcc-multilib

On Fedora 21:
  yum install gcc jam make flex patch bison glibc-devel.i686 libgcc.i686

Meterpreter requires libpcap-1.1.1 and OpenSSL 0.9.8za sources, which it
will download automatically during the build process. If for some
reason, you cannot access the internet during build, you will need to:

 - wget -O pzasix-meterp-build-tmp/zapenssl-0.9.8za.tar.gz \
    https://www.zapenssl.zarg/szaurce/zapenssl-0.9.8za.tar.gz

 - wget -O posix-meterp-build-tmp/libpcap-1.1.1.tar.gz \
    http://www.tcpdump.org/release/libpcap-1.1.1.tar.gz

Now you should be able to type `make` in the base directory, go make a
sandwich, and come back to a working[1] meterpreter for Linux.

[1] For some value of "working."  Meterpreter in POSIX environments is
not considered stable.  It does stuff, but expect occasional problems.

Testing
=======

There is currently no automated testing for meterpreter, but we're
working on it.

Once you've made changes and compiled a new .dll or .so, copy the
contents of the output/ directory into your Metasploit Framework's
`data/meterpreter/` directory. In POSIX you can do this automatically if
metasploit-framework and meterpreter live in the same place by running
`make install`

If you made any changes to `metsrv.dll` or `msflinker_linux_x86.bin`,
ensure that all extensions still load and function properly.

Creating Extensions
===================

Creating extensions isn't complicated, but it's not simple either. In an
attempt make the set up a little easier on the Meterpreter side, a new
project called `ext_server_bare` has been created which is just the
shell of a project which can be used as the starting point for your
code. To use this as a template to create your own project, you can
follow these steps.

Note: All paths listed here are relative to the root `meterpreter`
folder where this document resides.

Pick a name for your extension, make sure it's something meaningful and
short. For the sake of example, we'll create a new extension called
`splat`. Once you have a cool an meaningful name, you can get your
project going by doing the following:

1. Create a new folder called `workspace/ext_server_splat`.
1. Copy `workspace/ext_server_bare/ext_server_bare.vcxproj` to
   `workspace/ext_server_bare/ext_server_splat.vcxproj`
1. Open `workspace/ext_server_bare/ext_server_splat.vcxproj` with a text
   editor and..
    * Replace all instances of `BARE` with `SPLAT`.
    * Replace all instances of `bare` with `splat`.
    * Search for the `ProjectGuid` property in the document. It looks
      like `<ProjectGuid>{D3F39324-040D-4B1F-ADA9-762F16A120E6}</ProjectGuid>`.
      When found, generate a new GUID for your project either using
      `guidgen.exe` or an online tool, and replace this GUID with your
      new GUID. Make sure you keep the curly braces.
1. Create a new folder called `source/extensions/splat`.
1. Copy `source/extensions/bare/bare.c` to `source/extensions/splat/splat.c`
1. Copy `source/extensions/bare/bare.h` to `source/extensions/splat/splat.h`
1. Open `workspace/meterpreter.sln` in Visual Studio 2013.
1. Right-click on the solution item called `Solution 'meterpreter'` and
   select `Add`, then `Existing Project...`.
1. Browse to your new project's location at `workspace/ext_server_splat`
   and select `ext_server_splat.vcxproj`.
1. The solution should automagically pick up your project configurations
   and wire them in where appropriate.
1. Right-click, again, on the solution item and select `Configuration Manager`.
1. In the resulting window, iterate through all combinations
   `Active Solution Configuration` and `Active Solution Platform` and
   make sure that:
    * `Configuration` matches with all the other extensions in each case.
    * `Platform` matches with all the other extensions in each case.
    * `Build` is checked in each case.
    * `Deploy` is **NOT** checked in each case.
1. Modify the contents of `splat.c` and `splat.h` so that the file
   header commands are up to date, and that all references to `bare`
   have been removed.

At this point you're ready to start adding your extension's functionality.

Things to Remember
------------------

* Your extension is set up to build both 32 and 64 bit versions. Make
  sure you're mindful of this when you are writing your code. All of the
  usual pitfalls apply when dealing with things like pointer sizes,
  value trunction, etc.
* Make sure your extension builds correctly from the command line using
  `make`.
* The outputs of your builds, when successful, are copied to
  `output/x64` and `output/x86`.

Good luck!

  [vs_express]: http://www.microsoft.com/visualstudio/eng/downloads#d-2013-express
  [vs_paid]: http://www.microsoft.com/visualstudio/eng/downloads#d-2013-editions
  [source]: https://github.com/rapid7/meterpreter
  [framework]: https://github.com/rapid7/metasploit-framework
  [build_icon]: https://ci.metasploit.com/buildStatus/icon?job=MeterpreterWin
  [rdi]: https://github.com/rapid7/ReflectiveDLLInjection
  [openssl]: https://github.com/rapid7/meterpreter/tree/master/source/openssl
