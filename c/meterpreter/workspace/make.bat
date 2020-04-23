@ECHO OFF


SET VS_TITLE=Visual Studio 16 2019
SET VS_VER=VS2019
SET PTS_VER=v141_xp
SET BUILD_64=Y
SET BUILD_86=Y
SET SNIFFER=OFF
SET DBGTRACE=OFF
SET DBGTRACE_VERBOSE=OFF
set DO_BUILD=Y

IF EXIST "..\..\..\..\pssdk\PSSDK_VC%PSSDK_VER%_LIB\_Libs\pssdk_vc%PSSDK_VER%_mt.lib" SET SNIFFER=ON

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

IF "%BUILD_64%" == "Y" (
    @ECHO ====================================================================================
    @ECHO == Generating "%VS_TITLE%" w/ %PTS_VER% on x64 - TRACE "%DBGTRACE%-%DBGTRACE_VERBOSE%"
    @ECHO ====================================================================================
    cmake -G "%VS_TITLE%" -A x64 -T %PTS_VER% -S . -B build\%VS_VER%\x64 -Wno-dev -DBUILD_SNIFFER=%SNIFFER% -DDBGTRACE=%DBGTRACE% -DDBGTRACE_VERBOSE=%DBGTRACE_VERBOSE%
    if "%DO_BUILD%" == "Y" (
        @ECHO ====================================================================================
        @ECHO == Building "%VS_TITLE%" w/ %PTS_VER% on x64 - TRACE "%DBGTRACE%-%DBGTRACE_VERBOSE%"
        @ECHO ====================================================================================
        cmake --build build\%VS_VER%\x64 --config Release --clean-first -- /p:XPDeprecationWarning=false
    )
)

IF "%BUILD_86%" == "Y" (
    @ECHO ====================================================================================
    @ECHO == Generating "%VS_TITLE%" w/ %PTS_VER% on x86 - TRACE "%DBGTRACE%-%DBGTRACE_VERBOSE%"
    @ECHO ====================================================================================
    cmake -G "%VS_TITLE%" -A Win32 -T %PTS_VER% -S . -B build\%VS_VER%\Win32 -Wno-dev -DBUILD_SNIFFER=%SNIFFER% -DDBGTRACE=%DBGTRACE% -DDBGTRACE_VERBOSE=%DBGTRACE_VERBOSE%
    if "%DO_BUILD%" == "Y" (
        @ECHO ====================================================================================
        @ECHO == Building "%VS_TITLE%" w/ %PTS_VER% on x86 - TRACE "%DBGTRACE%-%DBGTRACE_VERBOSE%"
        @ECHO ====================================================================================
        cmake --build build\%VS_VER%\Win32 --config Release --clean-first -- /p:XPDeprecationWarning=false
    )
)
