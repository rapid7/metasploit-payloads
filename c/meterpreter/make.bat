@ECHO OFF
IF "%1"=="clean" GOTO CLEAN
IF "%1"=="docs" GOTO DOCS
IF "%VCINSTALLDIR%" == "" GOTO NEED_VS

SET PSSDK_VER=12

SET PREF=
IF EXIST "..\pssdk\PSSDK_VC%PSSDK_VER%_LIB\_Libs\pssdk_vc%PSSDK%_mt.lib" SET PREF=r7_

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

IF "%ERRORLEVEL%" == "0" (
  IF NOT EXIST "..\pssdk\" (
    ECHO "Unable to build ext_server_sniffer: PSSDK not found."
  ) else (
    IF NOT EXIST "..\pssdk\PSSDK_VC%PSSDK_VER%_LIB\_Libs\pssdk_vc%PSSDK_VER%_mt.lib" (
      ECHO "Unable to build ext_server_sniffer: Required PSSDK library version 'vc%PSSDK_VER%' not found."
    )
  )
)

GOTO :END

:CLEAN
IF EXIST "output\x86\" (
  del output\x86\ /S /Q
)
IF EXIST "output\x64\" (
  del output\x64\ /S /Q
)
GOTO :END

:DOCS
tools\doxygen\doxygen.exe doxygen.cnf
GOTO :END

:NEED_VS
ECHO "This command must be executed from within a Visual Studio Command prompt."
ECHO "This can be found under Microsoft Visual Studio 2013 -> Visual Studio Tools"

:END
