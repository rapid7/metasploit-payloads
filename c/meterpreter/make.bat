@ECHO OFF
IF "%VCINSTALLDIR%" == "" GOTO NEED_VS
SET PREF=
IF EXIST "..\pssdk\" SET PREF=r7_

IF "%1"=="x86" GOTO BUILD_X86
IF "%1"=="X64" GOTO BUILD_X64

ECHO "Building Meterpreter x64 and x86 (Release)"
SET PLAT=all
GOTO RUN

:BUILD_X86
ECHO "Building Meterpreter x86 (Release)"
SET PLAT=x86
GOTO RUN

:BUILD_X64
ECHO "Building Meterpreter x64 (Release)"
SET PLAT=x64
GOTO RUN

:RUN
PUSHD workspace
msbuild.exe make.msbuild /target:%PREF%%PLAT%

POPD
GOTO :END

:NEED_VS
ECHO "This command must be executed from within a Visual Studio Command prompt."
ECHO "This can be found under Microsoft Visual Studio 2012 -> Visual Studio Tools"

:END
