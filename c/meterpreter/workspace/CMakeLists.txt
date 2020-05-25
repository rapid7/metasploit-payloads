cmake_minimum_required(VERSION 3.15.7 FATAL_ERROR)

set(PROJECT_NAME meterpreter)

if(MSVC)
    cmake_policy(SET CMP0091 NEW)
endif()

project(${PROJECT_NAME} C)

option(DBGTRACE "Enable debug tracing" OFF)
option(DBGTRACE_VERBOSE "Enable verbose debug tracing" OFF)
option(BUILD_SNIFFER "Build the sniffer extension (requires PSSDK)" OFF)
option(USE_STATIC_MSVC_RUNTIMES "Use /MT instead of /MD in MSVC" ON)

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

set(MET_LIBS jpeg)

set(
    MET_EXTENSIONS
    ext_server_stdapi
    ext_server_priv
    ext_server_espia
    ext_server_incognito
    ext_server_unhook
    ext_server_winpmem
    ext_server_lanattacks
    ext_server_extapi
)

if(MSVC)
    set(
        MET_EXTENSIONS
        ${MET_EXTENSIONS}
        ext_server_peinjector
        ext_server_mimikatz
        ext_server_powershell
        ext_server_kiwi
        ext_server_python
    )
endif()

if(BUILD_SNIFFER)
    set(MET_EXTENSIONS ${MET_EXTENSIONS} ext_server_sniffer)
endif()

if(MSVC)
    set(
        MET_PLUGINS
        screenshot
        elevator
    )
endif()

set(
    MET_SERVERS
    metsrv
)

set(
    MET_DLLS
    ${MET_SERVERS}
    ${MET_PLUGINS}
    ${MET_EXTENSIONS}
)

set(
    MET_PROJECTS
    ${MET_LIBS}
    ${MET_DLLS}
)

foreach(MET_PROJECT ${MET_PROJECTS})
    add_subdirectory(${MET_PROJECT})
endforeach()
