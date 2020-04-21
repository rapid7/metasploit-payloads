# Native C meterpreter >

## Building - Windows
Meterpreter currently supports being built with multiple versions of Visual Studio, including the free/community editions.

### VS 2019
Building with VS2019 works with any version, including community. If you have an installation already, just make sure you have the following extra bits installed:

* Under `Workloads`:
    * `Desktop Development with C++`
* Under `Individual Components`:
    * `C++ Windows XP Support for VS 2017 (v141) tools [Deprecated]`

If you don't have an installation ready, follow these steps:

1. Install [Chocolatey](https://chocolatey.org).
2. Create a file called `.vsconfig` somewhere on disk with the following contents:
  ```
{
    "version": "1.0",
    "components": [
        "Microsoft.VisualStudio.Component.CoreEditor",
        "Microsoft.VisualStudio.Workload.CoreEditor",
        "Microsoft.VisualStudio.Component.NuGet",
        "Microsoft.VisualStudio.Component.Roslyn.Compiler",
        "Microsoft.Component.MSBuild",
        "Microsoft.VisualStudio.Component.TextTemplating",
        "Microsoft.VisualStudio.Component.IntelliCode",
        "Microsoft.VisualStudio.Component.VC.CoreIde",
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
        "Microsoft.VisualStudio.Component.Graphics.Tools",
        "Microsoft.VisualStudio.Component.VC.DiagnosticTools",
        "Microsoft.VisualStudio.Component.Windows10SDK.18362",
        "Microsoft.VisualStudio.Component.Debugger.JustInTime",
        "Microsoft.VisualStudio.Component.VC.Redist.14.Latest",
        "Microsoft.VisualStudio.ComponentGroup.NativeDesktop.Core",
        "Microsoft.VisualStudio.Component.VC.CMake.Project",
        "Microsoft.VisualStudio.Component.VC.ATL",
        "Microsoft.VisualStudio.Component.VC.ASAN",
        "Microsoft.Component.VC.Runtime.UCRTSDK",
        "Microsoft.VisualStudio.Workload.NativeDesktop",
        "Microsoft.VisualStudio.Component.WinXP"
    ]
}
  ```
3. Install VS with all the required components by running the following command in Powershell:
  ```
choco install visualstudio2019community -y --package-parameters "--config Path\To\Your\.vsconfig"
  ```

Note: A copy of this file is located in this repository under `c/meterpreter/vs-config/vs2019.vsconfig`.

### VS 2017
Building with VS2017 works with any version, including community. If you have an installation already, just make sure you have the following extra bits installed:

* Under `Workloads`:
    * `Desktop Development with C++`
* Under `Individual Components`:
    * `Windows XP support for C++`

If you don't have an installation ready, follow these steps:

1. Install [Chocolatey](https://chocolatey.org).
2. Create a file called `.vsconfig` somewhere on disk with the following contents:
  ```
{
    "version": "1.0",
    "components": [
        "Microsoft.VisualStudio.Workload.NativeDesktop",
        "microsoft.visualstudio.component.debugger.justintime",
        "microsoft.visualstudio.component.vc.diagnostictools",
        "microsoft.visualstudio.component.vc.cmake.project",
        "microsoft.visualstudio.component.vc.atl",
        "microsoft.visualstudio.componentgroup.nativedesktop.winxp"
    ]
}
  ```
3. Install VS with all the required components by running the following command in Powershell:
  ```
choco install visualstudio2017community -y --package-parameters "--config Path\To\Your\.vsconfig"
  ```

Note: A copy of this file is located in this repository under `c/meterpreter/vs-config/vs2017.vsconfig`.

### VS 2013
Download and install the `Visual Studio Express 2013 for Windows Desktop` edition. It is important that you use _this exact version_. To do this with Chocolatey, run the following:

```
choco install visualstudioexpress2013windowsdesktop -y
```

Nothing extra needs to be done.

## Dependencies

Windows Meterpreter has the following repositories set up as submodule dependencies:

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

At this point the dependencies will be ready to use and Meterpreter should be ready to
build.

## Running the Build

Open up a Visual Studio command prompt by selecting `Developer Command Prompt for VS201X`
from the Start menu. Alternatively you can run `vcvars32.bat` from an existing command
line prompt, just make sure it's the right one if you have multiple versions of VS
installed on your machine.

Once you have your environment variables set up, change to the root folder where the
meterpreter source is located. From here you can:

* Build the x86 version by running: `make x86`
* Build the x64 version by running: `make x64`
* Build both x86 and x64 versions by running: `make`

If you want to build binaries with the `v120_xp` toolset instead of `v141_xp` while using VS2017 or VS2019, you must first install VS2013 as shown above. Then, pass `v120_xp` as a parameter when running `make` (eg. `make v120_xp x64`).

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

# Testing

There is currently no automated testing for meterpreter, but we're working on it.

Once you've made changes and compiled a new .dll or .so, copy the contents of the output/ directory into your Metasploit Framework's `data/meterpreter/` directory.

If you made any changes to `metsrv.dll` ensure that all extensions still load and function properly.
