cmake_minimum_required(VERSION 3.15.7 FATAL_ERROR)

set(PROJECT_NAME meterpreter)

if(MSVC)
    cmake_policy(SET CMP0091 NEW)
endif()

project(${PROJECT_NAME} C)

option(DBGTRACE "Enable debug tracing" OFF)
option(DBGTRACE_VERBOSE "Enable verbose debug tracing" OFF)
option(USE_STATIC_MSVC_RUNTIMES "Use /MT instead of /MD in MSVC" ON)

option(BUILD_ALL "Build everything" ON)
option(BUILD_LIB_JPEG "Build JPEG lib" OFF)
option(BUILD_METSRV "Build METSRV" OFF)

option(BUILD_EXT_ALL "Build all extensions" OFF)
option(BUILD_EXT_SNIFFER "Build the SNIFFER extension (requires PSSDK)" OFF)
option(BUILD_EXT_STDAPI "Build the STDAPI extension" OFF)
option(BUILD_EXT_PRIV "Build the PRIV extension" OFF)
option(BUILD_EXT_EXTAPI "Build the EXTAPI extension" OFF)
option(BUILD_EXT_KIWI "Build the KIWI extension" OFF)
option(BUILD_EXT_ESPIA "Build the ESPIA extension" OFF)
option(BUILD_EXT_WINPMEM "Build the WINPMEM extension" OFF)
option(BUILD_EXT_UNHOOK "Build the UNHOOK extension" OFF)
option(BUILD_EXT_INCOGNITO "Build the INCOGNITO extension" OFF)
option(BUILD_EXT_LANATTACKS "Build the LANATTACKS extension" OFF)
option(BUILD_EXT_PYTHON "Build the PYTHON extension" OFF)
option(BUILD_EXT_POWERSHELL "Build the POWERSHELL extension" OFF)
option(BUILD_EXT_PEINJECTOR "Build the PEINJECTOR extension" OFF)
option(BUILD_EXT_BOFLOADER "Build the BOFLOADER extension" OFF)

option(BUILD_PLG_DUMPSAM "Build the DUMPSAM plugin" OFF)

if(BUILD_ALL)
    set(BUILD_LIB_JPEG ON)
    set(BUILD_METSRV ON)
    set(BUILD_EXT_ALL ON)
    # TODO: plugins
endif()

if(BUILD_EXT_ALL)
    set(BUILD_EXT_STDAPI ON)
    set(BUILD_EXT_PRIV ON)
    set(BUILD_EXT_EXTAPI ON)
    set(BUILD_EXT_KIWI ON)
    set(BUILD_EXT_ESPIA ON)
    set(BUILD_EXT_WINPMEM ON)
    set(BUILD_EXT_UNHOOK ON)
    set(BUILD_EXT_INCOGNITO ON)
    set(BUILD_EXT_LANATTACKS ON)
    set(BUILD_EXT_PYTHON ON)
    set(BUILD_EXT_POWERSHELL ON)
    set(BUILD_EXT_PEINJECTOR ON)
    set(BUILD_EXT_BOFLOADER ON)
endif()

if(BUILD_EXT_ESPIA)
    set(BUILD_LIB_JPEG ON)
endif()

if(BUILD_EXT_STDAPI)
    set(BUILD_LIB_JPEG ON)
endif()

if(USE_STATIC_MSVC_RUNTIMES)
    if(MSVC)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set(CMAKE_MINGW_FLAGS_COMMON "-static-libgcc -mwindows -fms-extensions -Wl,--enable-stdcall-fixup")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_MINGW_FLAGS_COMMON}")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_MINGW_FLAGS_COMMON} -static-libstdc++ -std=c++11")
    endif()
endif()

set(WORKSPACE_ROOT_DIR ${PROJECT_SOURCE_DIR})
set(MOD_DEF_DIR ${PROJECT_SOURCE_DIR}/../source/def/)
set(BIN_OUTPUT_DIR ${PROJECT_SOURCE_DIR}/../output/)
set(PSSDK_DIR ${PROJECT_SOURCE_DIR}/../../../../pssdk/)

if(MSVC)
    set(BUILD_ARCH ${CMAKE_GENERATOR_PLATFORM})
else()
    set(CMAKE_C_COMPILE_OPTIONS_PIC "")
    set(CMAKE_SHARED_LIBRARY_PREFIX "")
    set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")
endif()

if(BUILD_ARCH MATCHES "Win32")
    set(TARGET_ARCH "x86")
    set(IS_X86 true)
    set(IS_X64 false)
    set(BIN_SUBSYSTEM "4.0")
else()
    set(TARGET_ARCH "x64")
    set(IS_X86 false)
    set(IS_X64 true)
    set(BIN_SUBSYSTEM "5.01")
endif()

set(CMAKE_LIBRARY_ARCHITECTURE ${TARGET_ARCH} CACHE STRING "" FORCE)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
    message(STATUS "Build Type not specified, defaulting to 'Release'.")
endif()

set(IS_RELEASE true)
set(IS_DEBUG false)

if(CMAKE_BUILD_TYPE MATCHES "Release")
    if(MSVC)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3 /WX")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /WX /EHsc")
        string(REPLACE "O2" "O1" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
        string(REPLACE "Ob2" "Ob1" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
        string(REPLACE "O2" "O1" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
        string(REPLACE "Ob2" "Ob1" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
    endif()
else()
    # We only support "Release" or "Debug"
    set(CMAKE_BUILD_TYPE "Debug")
    set(IS_RELEASE false)
    set(IS_DEBUG true)
endif()

add_definitions(
    -DNDEBUG
    -D_WINDOWS
    -DWIN32
    -DWINVER=0x0501
)

if(DBGTRACE_VERBOSE)
    add_definitions(-DDEBUGTRACE=1)
elseif(DBGTRACE)
    add_definitions(-DDEBUGTRACE=0)
endif()

if(IS_X64)
    add_definitions(
        -DWIN64
        -D_WIN64
        -D_X64
        -DX64
    )
endif()

if(BUILD_LIB_JPEG)
    set(MET_LIBS jpeg)
endif()

if(BUILD_EXT_STDAPI)
    set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_stdapi)
endif()
if(BUILD_EXT_PRIV)
    set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_priv)
    set(BUILD_PLG_DUMPSAM ON)
endif()
if(BUILD_EXT_ESPIA)
    set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_espia)
endif()
if(BUILD_EXT_INCOGNITO)
    set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_incognito)
endif()
if(BUILD_EXT_UNHOOK)
    set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_unhook)
endif()
if(BUILD_EXT_WINPMEM)
    set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_winpmem)
endif()
if(BUILD_EXT_LANATTACKS)
    set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_lanattacks)
endif()
if(BUILD_EXT_EXTAPI)
    set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_extapi)
endif()
if(BUILD_EXT_KIWI)
    set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_kiwi)
endif()
if(BUILD_EXT_PEINJECTOR)
    set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_peinjector)
endif()
if(BUILD_EXT_BOFLOADER)
    set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_bofloader)
endif()

if(BUILD_PLG_DUMPSAM)
    set(MET_PLUGINS ${MET_PLUGINS} dump_sam)
endif()

if(BUILD_EXT_SNIFFER)
    if(MSVC)
        if(EXISTS "${PSSDK_DIR}")
            set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_sniffer)
        else()
            message(STATUS "[!] Unable to build SNIFFER: PSSDK is missing.")
        endif()
    else()
        message(STATUS "[!] Unable to build SNIFFER: not supported on Linux.")
    endif()
endif()

if(MSVC)
    if(BUILD_EXT_POWERSHELL)
        set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_powershell)
    endif()
    if(BUILD_EXT_PYTHON)
        set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_python)
    endif()
endif()

if(MSVC)
    set(
        MET_PLUGINS
        ${MET_PLUGINS}
        screenshot
        elevator
    )
endif()

if(BUILD_METSRV)
    set(MET_SERVERS metsrv)
endif()

set(MET_RDI_ASM ReflectiveDLLInjection)

set(
    MET_DLLS
    ${MET_SERVERS}
    ${MET_PLUGINS}
    ${MET_EXTENSIONS}
)

set(
    MET_PROJECTS
    ${MET_RDI_ASM}
    ${MET_LIBS}
    ${MET_DLLS}
)

foreach(MET_PROJECT ${MET_PROJECTS})
    add_subdirectory(${MET_PROJECT})
endforeach()
