cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

## linking errors c/meterpreter/source/client/console.c.o:console.c:(.text+0x1b5): undefined reference to `packet_get_result'


################### Variables. ####################
# Change if you want modify path or other values. #
###################################################

set(PROJECT_NAME metcli)
# Output Variables
set(OUTPUT_DEBUG ../../output/Debug/)
set(OUTPUT_RELEASE ../../output/Release/)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_RELEASE})
# Folders files
set(CPP_DIR_1 ../../source/client)
set(HEADER_DIR_1 ../../source/client)
set(HEADER_DIR_2 ../../source/common/)


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
   -D_DEBUG 
   -D_CONSOLE 
   -DUSE_DLL 
   -DMETERPRETER_EXPORTS 
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
   #add_subdirectory(../backcompat ${CMAKE_BINARY_DIR}/backcompat)
   add_subdirectory(../common ${OUTPUT_RELEASE})
else()
   link_directories("${OUTPUT_RELEASE}")
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
CMAKE_FORCE_C_COMPILER(${GNU_HOST}-gcc GNU)
# CMake doesn't automatically look for prefixed 'windres', do it manually:
SET(CMAKE_RC_COMPILER ${GNU_HOST}-windres)

if(MSVC)
   set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /W3 /Od /Zi /EHsc")
   set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /W3 /Zi /EHsc")
endif(MSVC)
if(NOT MSVC)
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
   if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
   endif()
endif(NOT MSVC)

################ Files ################
#   --   Add files to project.   --   #
#######################################

file(GLOB SRC_FILES
    ${CPP_DIR_1}/*.c
    ${HEADER_DIR_1}/*.h
)

include_directories( ${HEADER_DIR_1} )
include_directories( ${HEADER_DIR_2} )


# Add executable to build.
add_executable(${PROJECT_NAME} 
   ${SRC_FILES}
)

set(CMAKE_VERBOSE_MAKEFILE on)
SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "-export-all-symbols")

#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--export-dynamic") 

# Link with other dependencies.
#target_link_libraries(${PROJECT_NAME} backcompat common ) #todo backcompat

target_link_libraries(${PROJECT_NAME} common ws2_32 odbc32 odbccp32 crypt32 ReflectiveDLLInjection)

if(MSVC)
   target_link_libraries(${PROJECT_NAME} common.lib ws2_32.lib odbc32.lib odbccp32.lib )
endif(MSVC)
