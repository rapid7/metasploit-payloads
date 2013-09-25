@ECHO OFF
IF "%1"=="clean" GOTO CLEAN
IF "%1"=="docs" GOTO DOCS
IF "%VCINSTALLDIR%" == "" (
  ECHO "VC++ Environment not found, attempting to locate..."
  REM Attempt to load up the dev env variables if they're not
  REM set, saves people doing it manually
  SET SETUP="Microsoft Visual Studio 11.0\Common7\Tools\vsvars32.bat"
  IF EXIST "%ProgramFiles%\%SETUP%" (
    ECHO "Found at '%ProgramFiles%\%SETUP%'"
    "%ProgramFiles%\%SETUP%"
  )

  IF EXIST "%ProgramFiles(x86)%\%SETUP%" (
    ECHO "Found at '%ProgramFiles(x86)%\%SETUP%'"
    "%ProgramFiles(x86)%\%SETUP%"
  )

  REM If we still don't have what we need, then throw an error
  IF "%VCINSTALLDIR%" == "" GOTO NEED_VS
)

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
ECHO "This can be found under Microsoft Visual Studio 2012 -> Visual Studio Tools"

:END
