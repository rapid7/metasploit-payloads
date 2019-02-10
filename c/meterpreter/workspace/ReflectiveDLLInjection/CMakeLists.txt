cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

################### Variables. ####################
# Change if you want modify path or other values. #
###################################################

set(PROJECT_NAME ReflectiveDLLInjection)
# Output Variables
set(OUTPUT_DEBUG ../../output/Debug/)
set(OUTPUT_RELEASE ../../../output/Release/)
# Folders files

set(CPP_DIR_1 ../../source/ReflectiveDLLInjection/inject/src)
set(CPP_DIR_2 ../../source/DelayLoadMetSrv)
set(CPP_DIR_3 ../../source/ReflectiveDLLInjection/dll/src)
set(HEADER_DIR_1 ../../source/ReflectiveDLLInjection/common)
set(HEADER_DIR_2 ../../source/ReflectiveDLLInjection/inject/src)
set(HEADER_DIR_3 ../../source/DelayLoadMetSrv)
set(HEADER_DIR_4 ../../source/ReflectiveDLLInjection/dll/src)
set(HEADER_DIR_5 ../../source/common/)
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
   -D_DEBUG 
   -D_LIB 
   -DUNICODE
   -D_UNICODE
)

############## Artefacts Output #################
# Defines outputs , depending Debug or Release. #
#################################################

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${OUTPUT_DEBUG}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${OUTPUT_DEBUG}")
  set(CMAKE_EXECUTABLE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${OUTPUT_DEBUG}")
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

set(CMAKE_VERBOSE_MAKEFILE on)

# Dependencies : disable BUILD_DEPENDS to link with lib already build.
if(BUILD_DEPENDS)
   #add_subdirectory(platform/cmake/backcompat ${CMAKE_BINARY_DIR}/backcompat)
else()
   link_directories(../backcompat/Release/)
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
   set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /W3 /Od /EHsc")
   set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /W3 /EHsc")
endif(MSVC)
if(NOT MSVC)
set(CMAKE_LIBRARY_ARCHITECTURE x64 CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -target x86_64-w64-windows-gnu -I/usr/x86_64-w64-mingw32/include/ -L/usr/lib/gcc/x86_64-w64-mingw32/8.2.0/include/ -L/usr/x86_64-w64-mingw32/lib -Wfatal-errors -fmsc-version=${_MSC_VER} -fms-extensions -fms-compatibility -fdelayed-template-parsing ")
    
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I/usr/x86_64-w64-mingw32/include/ -std=c++11")
   if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
   endif()
endif(NOT MSVC)

################ Files ################
#   --   Add files to project.   --   #
#######################################

file(GLOB SRC_FILES
    ${CPP_DIR_1}/*.c
    ${CPP_DIR_2}/*.c
    ${CPP_DIR_3}/*.c
    ${HEADER_DIR_1}/*.h
    ${HEADER_DIR_2}/*.h
    ${HEADER_DIR_3}/*.h
    ${HEADER_DIR_4}/*.h
)

include_directories( ${HEADER_DIR_1} )
include_directories( ${HEADER_DIR_2} )
include_directories( ${HEADER_DIR_3} )
include_directories( ${HEADER_DIR_4} )
include_directories( ${HEADER_DIR_5} )

#include_directories("/usr/lib/gcc/x86_64-w64-mingw32/7.3-win32/include/c++/parallel/")
#include_directories("/usr/include/x86_64-linux-gnu/")

# Add library to build.
add_library(${PROJECT_NAME} STATIC
   ${SRC_FILES}
)

# Link with other dependencies.
target_link_libraries(${PROJECT_NAME} backcompat )
if(MSVC)
   target_link_libraries(${PROJECT_NAME} backcompat.lib )
endif(MSVC)
