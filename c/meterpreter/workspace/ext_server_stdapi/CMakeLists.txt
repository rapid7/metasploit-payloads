cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

################### Variables. ####################
# Change if you want modify path or other values. #
###################################################

set(PROJECT_NAME ext_server_stdapi)
# Output Variables
set(OUTPUT_DEBUG ../../output/Debug/)
set(OUTPUT_RELEASE ../../../output/Release/)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_RELEASE})

# Folders files
set(CPP_DIR_1 ../../source/extensions/stdapi/server/audio)
set(CPP_DIR_2 ../../source/extensions/stdapi/server/fs)
set(CPP_DIR_3 ../../source/extensions/stdapi/server)
set(CPP_DIR_4 ../../source/extensions/stdapi/server/net/config)
set(CPP_DIR_5 ../../source/extensions/stdapi/server/net)
set(CPP_DIR_6 ../../source/extensions/stdapi/server/net/socket)
set(CPP_DIR_7 ../../source/extensions/stdapi/server/sys)
set(CPP_DIR_8 ../../source/extensions/stdapi/server/sys/process)
set(CPP_DIR_9 ../../source/extensions/stdapi/server/sys/registry)
set(CPP_DIR_10 ../../source/extensions/stdapi/server/sys/power)
set(CPP_DIR_11 ../../source/extensions/stdapi/server/sys/eventlog)
set(CPP_DIR_12 ../../source/extensions/stdapi/server/sys/config)
set(CPP_DIR_13 ../../source/extensions/stdapi/server/ui)
set(CPP_DIR_14 ../../source/extensions/stdapi/server/railgun)
set(CPP_DIR_15 ../../source/extensions/stdapi/server/webcam)
set(HEADER_DIR_1 ../../source/extensions/stdapi/server)
set(HEADER_DIR_2 ../../source/extensions/stdapi/server/sys/config)
set(HEADER_DIR_3 ../../source/extensions/stdapi)
set(HEADER_DIR_4 ../../source/extensions/stdapi/server/net)
set(HEADER_DIR_5 ../../source/extensions/stdapi/server/net/socket)
set(HEADER_DIR_6 ../../source/extensions/stdapi/server/sys)
set(HEADER_DIR_7 ../../source/extensions/stdapi/server/sys/process)
set(HEADER_DIR_8 ../../source/extensions/stdapi/server/sys/registry)
set(HEADER_DIR_9 ../../source/extensions/stdapi/server/sys/power)
set(HEADER_DIR_10 ../../source/extensions/stdapi/server/sys/eventlog)
set(HEADER_DIR_11 ../../source/extensions/stdapi/server/ui)
set(HEADER_DIR_12 ../../source/extensions/stdapi/server/railgun)
set(HEADER_DIR_13 ../../source/extensions/stdapi/server/webcam)
set(HEADER_DIR_14 ../../source/extensions/stdapi/server/audio)
set(HEADER_DIR_15 ../../source/extensions/stdapi/server/fs)
set(HEADER_DIR_16 ../../source/ReflectiveDLLInjection/common)
set(HEADER_DIR_17 ../../source/extra_includes)
set(HEADER_DIR_18 ../../source/jpeg-8)


############## CMake Project ################
#        The main options of project        #
#############################################

project(${PROJECT_NAME} C)

# Define Release by default.
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
  message(STATUS "Build type not specified: Use Release by default.")
endif(NOT CMAKE_BUILD_TYPE)

# Definition of Macros
add_definitions(
   -D__GNUC__
   -DNDEBUG 
   -D__in=SAL__in
   -D__inout=SAL__inout
   -D__out_bcount_part_opt=SAL__out_bcount_part_opt
   -D__in_ecount=SAL__in_ecount
   -DHAVE_BOOLEAN
   -DMTP_EXTENSION
   #-DUSE_DLL



)

############## Artefacts Output #################
# Defines outputs , depending Debug or Release. #
#################################################

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${OUTPUT_DEBUG}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${OUTPUT_DEBUG}")
  set(CMAKE_EXECUTABLE_OUTPUT_DIRECTORY "${OUTPUT_DEBUG}")
else()
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${OUTPUT_RELEASE}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${OUTPUT_RELEASE}")
  set(CMAKE_EXECUTABLE_OUTPUT_DIRECTORY "${OUTPUT_RELEASE}")
endif()

################### Dependencies ##################
# Add Dependencies to project.                    #
###################################################

option(BUILD_DEPENDS 
   "Build other CMake project." 
   OFF 
)

# Dependencies : disable BUILD_DEPENDS to link with lib already build.
if(BUILD_DEPENDS)
   #add_subdirectory(../backcompat ${OUTPUT_RELEASE})
   add_subdirectory(../../common ${OUTPUT_RELEASE})
   add_subdirectory(../../ReflectiveDLLInjection ${OUTPUT_RELEASE})
   add_subdirectory(../../metsrv ${OUTPUT_RELEASE})
else()
   #add_subdirectory(../metsrv ${OUTPUT_RELEASE})
   link_directories(${OUTPUT_RELEASE})
   link_directories(../../output/Release)
endif()

################# Flags ################
# Defines Flags for Windows and Linux. #
########################################
SET(CMAKE_SYSTEM_NAME Windows)
include(CMakeForceCompiler)
IF("${GNU_HOST}" STREQUAL "")
    SET(GNU_HOST x86_64-w64-mingw32)
ENDIF()
# Prefix detection only works with compiler id "GNU"
#CMAKE_FORCE_C_COMPILER(${GNU_HOST}-gcc GNU)
# CMake doesn't automatically look for prefixed 'windres', do it manually:
SET(CMAKE_RC_COMPILER ${GNU_HOST}-windres)
set( _MSC_VER 1910 )
SET(CMAKE_C_COMPILER clang)

if(MSVC)
   set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /W3 /EHsc")
   set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /W3 /EHsc")
endif(MSVC)
if(NOT MSVC)
set(CMAKE_LIBRARY_ARCHITECTURE x64 CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -target x86_64-w64-windows-gnu -I/usr/x86_64-w64-mingw32/include/ -delayload -undefined dynamic_lookup  -Wvisibility -Wfatal-errors -fmsc-version=${_MSC_VER} -fms-extensions -fms-compatibility -fdelayed-template-parsing ")
SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -delayload -undefined dynamic_lookup")
set (CMAKE_SHARED_LINKER_FLAGS "-Wl,--as-needed -delayload -undefined dynamic_lookup")

   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wvisibility")
   if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
   endif()
endif(NOT MSVC)

################ Files ################
#   --   Add files to project.   --   #
#######################################

file(GLOB SRC_FILES
    ${CPP_DIR_1}/*.c
    ${CPP_DIR_1}/*.cpp
    ${CPP_DIR_2}/*.c
    ${CPP_DIR_2}/*.cpp
    ${CPP_DIR_3}/*.c
    ${CPP_DIR_3}/*.cpp
    ${CPP_DIR_4}/*.c
    ${CPP_DIR_4}/*.cpp
    ${CPP_DIR_5}/*.c
    ${CPP_DIR_5}/*.cpp
    ${CPP_DIR_6}/*.c
    ${CPP_DIR_6}/*.cpp
    ${CPP_DIR_7}/*.c
    ${CPP_DIR_7}/*.cpp
    ${CPP_DIR_8}/*.c
    ${CPP_DIR_8}/*.cpp
    ${CPP_DIR_9}/*.c
    ${CPP_DIR_9}/*.cpp
    ${CPP_DIR_10}/*.c
    ${CPP_DIR_10}/*.cpp
    ${CPP_DIR_11}/*.c
    ${CPP_DIR_11}/*.cpp
    ${CPP_DIR_12}/*.c
    ${CPP_DIR_12}/*.cpp
    ${CPP_DIR_13}/*.c
    ${CPP_DIR_13}/*.cpp
    ${CPP_DIR_14}/*.c
    ${CPP_DIR_14}/*.cpp
    ${CPP_DIR_15}/*.c
    ${CPP_DIR_15}/*.cpp
)

include_directories( ${HEADER_DIR_1} )
include_directories( ${HEADER_DIR_2} )
include_directories( ${HEADER_DIR_3} )
include_directories( ${HEADER_DIR_4} )
include_directories( ${HEADER_DIR_5} )
include_directories( ${HEADER_DIR_6} )
include_directories( ${HEADER_DIR_7} )
include_directories( ${HEADER_DIR_8} )
include_directories( ${HEADER_DIR_9} )
include_directories( ${HEADER_DIR_10} )
include_directories( ${HEADER_DIR_11} )
include_directories( ${HEADER_DIR_12} )
include_directories( ${HEADER_DIR_13} )
include_directories( ${HEADER_DIR_14} )
include_directories( ${HEADER_DIR_15} )
include_directories( ${HEADER_DIR_16} ) #ReflectiveDLLInjection
include_directories( ${HEADER_DIR_17} )
include_directories( ${HEADER_DIR_18} )

set( CMAKE_C_COMPILE_OPTIONS_PIC "" ) 

add_link_options(-Wl,--unresolved-symbols=ignore-in-shared-libs )# Add library to build.

add_library(${PROJECT_NAME} SHARED
   ${SRC_FILES}
)

set(CMAKE_VERBOSE_MAKEFILE ON)

link_directories(/usr/x86_64-w64-mingw32/lib/)
# Link with other dependencies.
#target_link_libraries(${PROJECT_NAME} backcompat common metsrv ReflectiveDLLInjection )
target_link_libraries(${PROJECT_NAME} common ReflectiveDLLInjection psapi winmm iphlpapi shlwapi ws2_32 odbc32 odbccp32 mpr crypt32 wininet winhttp ole32 netapi32 jpeg )
if(MSVC)
   target_link_libraries(${PROJECT_NAME} psapi.lib winmm.lib backcompat.lib iphlpapi.lib shlwapi.lib ws2_32.lib odbc32.lib odbccp32.lib metsrv.lib jpeg.lib )
endif(MSVC)