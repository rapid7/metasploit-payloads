cmake_minimum_required(VERSION 3.15.7 FATAL_ERROR)

set(PROJECT_NAME meterpreter)

cmake_policy(SET CMP0091 NEW)
project(${PROJECT_NAME} C CXX)

option(DBGTRACE "Enable debug tracing" OFF)
option(DBGTRACE_VERBOSE "Enable verbose debug tracing" OFF)
option(BUILD_SNIFFER "Build the sniffer extension (requires PSSDK)" OFF)
option(USE_STATIC_MSVC_RUNTIMES "Use /MT instead of /MD in MSVC" ON)
if( USE_STATIC_MSVC_RUNTIMES )
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

set(WORKSPACE_ROOT_DIR ${PROJECT_SOURCE_DIR})
set(BIN_OUTPUT_DIR ${PROJECT_SOURCE_DIR}/../output)
set(PSSDK_DIR ${PROJECT_SOURCE_DIR}/../../../../pssdk)

if(CMAKE_GENERATOR_PLATFORM MATCHES "Win32")
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

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
    message(STATUS "Build Type not specified, defaulting to 'Release'.")
endif()

set(IS_RELEASE true)
set(IS_DEBUG false)

if(CMAKE_BUILD_TYPE MATCHES "Release")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3 /WX")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /WX /EHsc")
    string(REPLACE "O2" "O1" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    string(REPLACE "Ob2" "Ob1" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    string(REPLACE "O2" "O1" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
    string(REPLACE "Ob2" "Ob1" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
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
if(IS_X86)
    set(MET_LIBS backcompat ${MET_LIBS})
endif()

foreach(MET_LIB ${MET_LIBS})
    add_subdirectory(${MET_LIB})
endforeach()

set(
    MET_DLLS
    metsrv
    elevator
    screenshot
    ext_server_espia
    ext_server_priv
    ext_server_extapi
    ext_server_incognito
    ext_server_lanattacks
    ext_server_peinjector
    ext_server_winpmem
    ext_server_unhook
    ext_server_powershell
    ext_server_kiwi
    ext_server_python
    ext_server_stdapi
)

if(BUILD_SNIFFER)
    set(MET_DLLS ${MET_DLLS} ext_server_sniffer)
endif()

foreach(MET_DLL ${MET_DLLS})
    add_subdirectory(${MET_DLL})
endforeach()
