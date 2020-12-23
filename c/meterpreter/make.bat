@ECHO OFF
IF "%1"=="clean" GOTO CLEAN
IF "%1"=="docs" GOTO DOCS
IF "%VCINSTALLDIR%" == "" GOTO NEED_VS
IF NOT EXIST "source\ReflectiveDLLInjection\.git" (
  ECHO Meterpreter's submodule dependencies can't be found.
  ECHO From your git console, please run:
  ECHO   $ git submodule init ^&^& git submodule update
  GOTO END
)

SET PSSDK_VER=19
SET PTS_VER=v141_xp

IF "%1"=="v120_xp" SET PTS_VER=%1
IF "%2"=="v120_xp" SET PTS_VER=%2
IF "%3"=="v120_xp" SET PTS_VER=%3

IF "%VisualStudioVersion%" == "12.0" (
    SET PSSDK_VER=12
    SET PTS_VER=v120_xp
)

SET PREF=
IF EXIST "..\..\..\pssdk\PSSDK_VC%PSSDK_VER%_LIB\_Libs\pssdk_vc%PSSDK_VER%_mt.lib" SET PREF=r7_

IF "%1"=="x86" GOTO BUILD_X86
IF "%1"=="X86" GOTO BUILD_X86
IF "%1"=="x64" GOTO BUILD_X64
IF "%1"=="X64" GOTO BUILD_X64
IF "%1"=="debug_x86" GOTO DEBUG_BUILD_X86
IF "%1"=="debug_x64" GOTO DEBUG_BUILD_X64
IF "%1"=="debug_X86" GOTO DEBUG_BUILD_X86
IF "%1"=="debug_X64" GOTO DEBUG_BUILD_X64

ECHO "Building Meterpreter x64 and x86 (Release)"
SET PLAT=all
GOTO RUN

:BUILD_X86
ECHO "Building Meterpreter x86 (Release)"
SET PLAT=x86
GOTO RUN

:DEBUG_BUILD_X86
ECHO "Building Meterpreter x86 (Debug)"
SET PREF=debug_
SET PLAT=x86
GOTO RUN

:BUILD_X64
ECHO "Building Meterpreter x64 (Release)"
SET PLAT=x64
GOTO RUN

:DEBUG_BUILD_X64
ECHO "Building Meterpreter x64 (Debug)"
SET PREF=debug_
SET PLAT=x64
GOTO RUN

:RUN
PUSHD workspace
msbuild.exe make.msbuild /target:%PREF%%PLAT% /p:PlatformToolset=%PTS_VER%
POPD

IF "%ERRORLEVEL%" == "0" (
  IF NOT EXIST "..\..\..\pssdk\" (
    ECHO Unable to build ext_server_sniffer:
    ECHO PSSDK directory not found.
    ECHO This is normal if you do not expect to have access to Rapid7 proprietary
    ECHO sniffer source. Meterpreter will still function normally without this.
  ) else (
    IF NOT EXIST "..\..\..\pssdk\PSSDK_VC%PSSDK_VER%_LIB\_Libs\pssdk_vc%PSSDK_VER%_mt.lib" (
      ECHO Unable to build ext_server_sniffer:
      ECHO PSSDK lib version 'vc%PSSDK_VER%' not found.
      ECHO This is normal if you do not expect to have access to Rapid7 proprietary
      ECHO sniffer source. Meterpreter will still function normally without this.
    )
  )
)

FOR /F "usebackq tokens=1,2 delims==" %%i IN (`wmic os get LocalDateTime /VALUE 2^>NUL`) DO IF '.%%i.'=='.LocalDateTime.' SET LDT=%%j
SET LDT=%LDT:~0,4%-%LDT:~4,2%-%LDT:~6,2% %LDT:~8,2%:%LDT:~10,2%:%LDT:~12,6%
echo Finished %ldt%

GOTO END

:CLEAN
IF EXIST "output\" (
  del output\ /S /Q
)
GOTO END

:DOCS
tools\doxygen\doxygen.exe doxygen.cnf
GOTO END

:NEED_VS
ECHO "This command must be executed from within a Visual Studio Command prompt."
ECHO "This can be found under Microsoft Visual Studio (2013|2017|2019) -> Visual Studio Tools"

:END
