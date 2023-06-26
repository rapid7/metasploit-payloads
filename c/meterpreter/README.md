# Windows Native C meterpreter >

Before you do anything, you're going to need to make sure you have the dependencies set up. Windows Meterpreter has the following repositories set up as submodule dependencies:

* [Reflective DLL Injection](https://github.com/rapid7/ReflectiveDLLInjection)
* [Dependencies](https://github.com/rapid7/meterpreter-deps)

For Meterpreter to build correctly, these submodules must be initialised and updated,
like so:

```
git clone https://github.com/rapid7/metasploit-payloads
cd metasploit-payloads
git submodule init
git submodule update
```

With the code checked out and the submodules updated, you're ready to run a build. Here you have two main options:

* Compile Windows Meterpreter on Windows with VS2013, VS2017 or VS2019.
* Cross-compile Windows Meterpreter on Linux, either directly on your host or via a Docker container.

## Building - Windows on Windows
Meterpreter currently supports being built with multiple versions of Visual Studio, including the free/community editions.
Before building make sure to disable antivirus/windows defender.

### VS 2019
Building with VS2019 works with any version, including community. If you have an installation already, just make sure you have the following extra bits installed:

* Under `Workloads`:
    * `Desktop Development with C++`
* Under `Individual Components`:
    * `C++ Windows XP Support for VS 2017 (v141) tools [Deprecated]`

If you don't have an installation ready, follow these steps:

1. Install [Chocolatey](https://chocolatey.org).
2. Install VS with all the required components by running the following command in Powershell:
  ```
choco install visualstudio2019community -y --package-parameters "--config C:\YOUR_PATH\metasploit-payloads\c\meterpreter\vs-configs\vs2019.vsconfig"
  ```

### VS 2017
Building with VS2017 works with any version, including community. If you have an installation already, just make sure you have the following extra bits installed:

* Under `Workloads`:
    * `Desktop Development with C++`
* Under `Individual Components`:
    * `Windows XP support for C++`

If you don't have an installation ready, follow these steps:

1. Install [Chocolatey](https://chocolatey.org).
2. Install VS with all the required components by running the following command in Powershell:
  ```
choco install visualstudio2017community -y --package-parameters "--config C:\YOUR_PATH\metasploit-payloads\c\meterpreter\vs-configs\vs2017.vsconfig"
  ```

Note: A copy of this file is located in this repository under `c/meterpreter/vs-config/vs2017.vsconfig`.

### VS 2013
Download and install the `Visual Studio Express 2013 for Windows Desktop` edition. It is important that you use _this exact version_. To do this with Chocolatey, run the following:

```
choco install visualstudioexpress2013windowsdesktop -y
```

Nothing extra needs to be done.

At this point the dependencies will be ready to use and Meterpreter should be ready to
build.

### Running the Build

Open up a Visual Studio command prompt by selecting `Developer Command Prompt for VS201X`
from the Start menu. Alternatively you can run `vcvars32.bat` from an existing command
line prompt, just make sure it's the right one if you have multiple versions of VS
installed on your machine.

Once you have your environment variables set up, change to the root folder where the
meterpreter source is located. From here you can:

* Build the x86 version by running: `make x86`
* Build the x64 version by running: `make x64`
* Build both x86 and x64 versions by running: `make`

If you want to build binaries with the `v120_xp` toolset instead of `v141_xp` while using VS2017 or VS2019, you must first install VS2013 as shown above. Then, pass `v120_xp` as a parameter when running `make` (eg. `make v120_xp x64`). The Rapid7 build automation uses v120_xp to build the distributed binaries, so projects must build with that platform toolset.

The compiled binaries are written to the `output` folder.

If you are not a Rapid7 employee, make sure you build the source using the `debug` or `release` configurations when inside Visual Studio. If you attempt to build `r7_debug` or `r7_release` you will get compiler errors due to missing libraries.

If you build the source from the command line the toolset will choose the most appropriate build configuration for you and hence calling `make` should "Just Work&trade;".

If you are a Rapid7 employee you will need the PSSDK source in order to build the extra components using the `r7_*` build configurations.

If submodule dependencies are not found on the file system, the script should display an error message like so:

```
Meterpreter's submodule dependencies can't be found.
From your git console, please run:
  $ git submodule init && git submodule update
```

## Building - Windows on Linux

Configuring a build environment on Linux is a bit of a pain in the rear and is also very likely to change in the near future as we move towards building via clang and making use of llvm for things such as transformations. As a result, we would recommend that you don't try to set up a host environment just yet. The best option is to make use of the docker container that has been built and configured to do the builds for you.

The docker container should be published to the Internet. However, if it isn't, you can build it yourself by running:

```
make docker-container
```

This takes a while, so be patient.

If you want to use the pre-built container all you have to do is run a normal build, and the container image will be downloaded if it's not present in the current list of locally available images. To do this, run:
```
make docker
```

### Making the components

As mentioned above, to build the entire supported suite of binaries, run the following:
```
make docker
```

It's possible to build architecture-specific versions by appending the architecture in question.
```
# Build x64 only
make docker-x64
# Build x86 only
make docker-x86
```

There are a number of other options in the `Makefile`, including the ability to build individual sets. Here are some examples:
```
# Build metsrv for all architectures
make docker-metsrv
# Build stdapi for x86
make docker-ext-stdapi-x86
```

All binaries are copied to the local `output` folder. All activites are done under the context of the current user even inside the container, so generated binaries should have the correct ownership.

### Notes

* The builds on Linux aren't not 100% clean yet, this is something we are working on. Expect to see a few warnings pop up.
* We aren't yet able to build the `python` and `powershell` extensions thanks to some assembly magic and COM nonsense. This is something we hope to resolve in the near future.
* These binaries _might_ not be ABI compatible with binaries created with Visual Studio. There may be edge cases where memory is allocated in one location and freed in another, and hence if the allocators don't match you end up with pain and suffering. We'll be working on something to resolve this as well so that these binaries can be mixed and matched.

# Testing

There is currently no automated testing for meterpreter, but we're working on it.

Once you've made changes and compiled a new .dll or .so, copy the contents of the output/ directory into your Metasploit Framework's `data/meterpreter/` directory.

If you made any changes to `metsrv.dll` ensure that all extensions still load and function properly.

# Debugging
[Debugging wiki page](https://github.com/rapid7/metasploit-payloads/wiki/Debugging-Meterpreter(s))

For debugging it helps to have two machines ready, one Windows (to be setup as described earlier to build meterpreter)
and one Ubuntu (ths is where you would have your [framework dev envrionment](https://github.com/rapid7/metasploit-framework/wiki/Setting-Up-a-Metasploit-Development-Environment)), these can both be VMs.

`git clone` this repo onto your framework development machine and then map it as a network drive to the Windows machine.
Don't forget to run `git submodule init && git submodule update`.
Once that's done you can load the project up in Visual Studio as described in the "Building - Windows on Windows" section of the Readme.

To build in Debug mode all you need to do in the Visual Studio UI is select Debug from the configuration dropwdown (as opposed to Release or r7_Release).
Now select Win32 or x64 depending on whether you want to build for 32 or 64 bit meterpreter (or both) and then (re)build the solution.

Once you compile code, you need to link it to Framework so you can test it.  Because other people at R7 are super smart, this is not so bad.
Go to a terminal in the payloads repo that can see both framework and payloads (I do this on my ubuntu machine)
Run make install-windows
```
$ make install-windows
Installing Windows payloads
```
All this does is copy the generated `.dll`'s to `metasploit-framework/data/meterpreter`

Once the dlls are in place, you should get a warning about using local payloads when you generate a session:
```
WARNING: Local file /home/dwelch/dev/metasploit-framework/data/meterpreter/metsrv.x64.dll is being used
WARNING: Local files may be incompatible with the Metasploit Framework
```

Once that is in place, run debugView as admin on the machine running the payload. Be sure to select "Global_Win32" messages in the "Capture" dropdown box.
