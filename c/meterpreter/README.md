# Native C meterpreter >

## Building - Windows
==================

Meterpreter currently supports being built with multiple versions of Visual Studio, including the free/community editions.

### VS 2019
Download and install any version (including community) and make sure the `v141_xp` platform toolset is added as an additional option.

### VS 2017
Download and install any version (including community) and make sure the `Windows XP tools for C++` are installed.

### VS 2013
Download and install the `Visual Studio Express 2013 for Windows Desktop` edition. This is important.

Windows Meterpreter has the following repositories set up as submodule dependencies:

* [Reflective DLL Injection][rdi]
* [Dependencies][deps]

For Meterpreter to build correctly, these submodules must be initialised and updated,
like so:

``` bash
$ git clone https://github.com/rapid7/metasploit-payloads
$ cd metasploit-payloads
$ git submodule init && git submodule update
```

At this point the dependencies will be ready to use and Meterpreter should be ready to
build.

Running the Build
-----------------

Open up a Visual Studio command prompt by selecting `Developer Command Prompt for VS201X`
from the Start menu. Alternatively you can run `vcvars32.bat` from an existing command
line prompt, just make sure it's the right one if you have multiple versions of VS
installed on your machine.

Once you have your environment variables set up, change to the root folder where the
meterpreter source is located. From here you can:

* Build the x86 version by running: `make x86`
* Build the x64 version by running: `make x64`
* Build both x86 and x64 versions by running: `make`

The compiled binaries are written to the `output`.

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

Testing
=======

There is currently no automated testing for meterpreter, but we're
working on it.

Once you've made changes and compiled a new .dll or .so, copy the
contents of the output/ directory into your Metasploit Framework's
`data/meterpreter/` directory.

If you made any changes to `metsrv.dll` ensure that all extensions still load
and function properly.

  [rdi]: https://github.com/rapid7/ReflectiveDLLInjection
  [deps]: https://github.com/rapid7/meterpreter-deps
