@ECHO OFF

IF "%1"=="clean" GOTO CLEAN
IF "%1"=="docs" GOTO DOCS

IF NOT EXIST "source\ReflectiveDLLInjection\.git" (
  ECHO Meterpreter's submodule dependencies can't be found.
  ECHO From your git console, please run:
  ECHO   git submodule init
  ECHO   git submodule update
  GOTO END
)

SET VS_TITLE=Visual Studio 16 2019
SET VS_VER=VS2019
SET PTS_VER=v141_xp
SET PSSDK_VER=19
SET BUILD_64=Y
SET BUILD_86=Y
SET SNIFFER=OFF
SET DBGTRACE=OFF
SET DBGTRACE_VERBOSE=OFF
set DO_BUILD=Y

IF "%1" == "NOBUILD" SET DO_BUILD=N
IF "%2" == "NOBUILD" SET DO_BUILD=N
IF "%3" == "NOBUILD" SET DO_BUILD=N
IF "%4" == "NOBUILD" SET DO_BUILD=N
IF "%5" == "NOBUILD" SET DO_BUILD=N

IF "%1" == "v120_xp" SET PTS_VER=%1
IF "%2" == "v120_xp" SET PTS_VER=%2
IF "%3" == "v120_xp" SET PTS_VER=%3
IF "%4" == "v120_xp" SET PTS_VER=%4
IF "%5" == "v120_xp" SET PTS_VER=%5

IF "%1" == "VS2013" SET VS_VER=%1
IF "%2" == "VS2013" SET VS_VER=%2
IF "%3" == "VS2013" SET VS_VER=%3
IF "%4" == "VS2013" SET VS_VER=%4
IF "%5" == "VS2013" SET VS_VER=%5

REM If VS2013 is used, we have to stick to v121_xp
IF "%VS_VER%" == "VS2013" (
    SET VS_TITLE=Visual Studio 12 2013
    SET PTS_VER=v120_xp
    SET PSSDK_VER=12
)

IF "%1" == "x86" SET BUILD_64=N
IF "%2" == "x86" SET BUILD_64=N
IF "%3" == "x86" SET BUILD_64=N
IF "%4" == "x86" SET BUILD_64=N
IF "%5" == "x86" SET BUILD_64=N

IF "%1" == "x64" SET BUILD_86=N
IF "%2" == "x64" SET BUILD_86=N
IF "%3" == "x64" SET BUILD_86=N
IF "%4" == "x64" SET BUILD_86=N
IF "%5" == "x64" SET BUILD_86=N

IF "%1" == "DBGTRACE" SET DBGTRACE=ON
IF "%2" == "DBGTRACE" SET DBGTRACE=ON
IF "%3" == "DBGTRACE" SET DBGTRACE=ON
IF "%4" == "DBGTRACE" SET DBGTRACE=ON
IF "%5" == "DBGTRACE" SET DBGTRACE=ON

IF "%1" == "DBGTRACE_VERBOSE" SET DBGTRACE_VERBOSE=ON
IF "%2" == "DBGTRACE_VERBOSE" SET DBGTRACE_VERBOSE=ON
IF "%3" == "DBGTRACE_VERBOSE" SET DBGTRACE_VERBOSE=ON
IF "%4" == "DBGTRACE_VERBOSE" SET DBGTRACE_VERBOSE=ON
IF "%5" == "DBGTRACE_VERBOSE" SET DBGTRACE_VERBOSE=ON

SET TRACE_MSG=%DBGTRACE%
IF "%DBGTRACE_VERBOSE%" == "ON" SET TRACE_MSG=VERBOSE

IF EXIST "..\..\..\pssdk\PSSDK_VC%PSSDK_VER%_LIB\_Libs\pssdk_vc%PSSDK_VER%_mt.lib" SET SNIFFER=ON

IF "%BUILD_64%" == "Y" (
    @ECHO ====================================================================================
    @ECHO == Generating "%VS_TITLE%" w/ %PTS_VER% on x64 ^(Trace: %TRACE_MSG%^)
    @ECHO ====================================================================================
    cmake -G "%VS_TITLE%" -A x64 -T %PTS_VER% -S workspace -B workspace\build\%VS_VER%_%PTS_VER%\x64 -Wno-dev -DBUILD_SNIFFER=%SNIFFER% -DDBGTRACE=%DBGTRACE% -DDBGTRACE_VERBOSE=%DBGTRACE_VERBOSE%
    if "%DO_BUILD%" == "Y" (
        @ECHO ====================================================================================
        @ECHO == Building "%VS_TITLE%" w/ %PTS_VER% on x64
        @ECHO ====================================================================================
        cmake --build workspace\build\%VS_VER%_%PTS_VER%\x64 --config Release --clean-first -- /p:XPDeprecationWarning=false
    )
)

IF "%BUILD_86%" == "Y" (
    @ECHO ====================================================================================
    @ECHO == Generating "%VS_TITLE%" w/ %PTS_VER% on x86 ^(Trace: %TRACE_MSG%^)
    @ECHO ====================================================================================
    cmake -G "%VS_TITLE%" -A Win32 -T %PTS_VER% -S workspace -B workspace\build\%VS_VER%_%PTS_VER%\Win32 -Wno-dev -DBUILD_SNIFFER=%SNIFFER% -DDBGTRACE=%DBGTRACE% -DDBGTRACE_VERBOSE=%DBGTRACE_VERBOSE%
    if "%DO_BUILD%" == "Y" (
        @ECHO ====================================================================================
        @ECHO == Building "%VS_TITLE%" w/ %PTS_VER% on x86
        @ECHO ====================================================================================
        cmake --build workspace\build\%VS_VER%_%PTS_VER%\Win32 --config Release --clean-first -- /p:XPDeprecationWarning=false
    )
)

FOR /F "usebackq tokens=1,2 delims==" %%i IN (`wmic os get LocalDateTime /VALUE 2^>NUL`) DO IF '.%%i.'=='.LocalDateTime.' SET LDT=%%j
SET LDT=%LDT:~0,4%-%LDT:~4,2%-%LDT:~6,2% %LDT:~8,2%:%LDT:~10,2%:%LDT:~12,6%
echo Finished %ldt%
GOTO END

:CLEAN
IF EXIST "output\" (
  del output\ /S /Q
  del workspace\build\ /S /Q
)
GOTO END

:DOCS
tools\doxygen\doxygen.exe doxygen.cnf 
GOTO END


:END
