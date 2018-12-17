cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

################### Variables. ####################
# Change if you want modify path or other values. #
###################################################

set(PROJECT_NAME ext_server_python)
# Output Variables
set(OUTPUT_DEBUG ../../output/Debug/)
set(OUTPUT_RELEASE ../../output/Release/)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_RELEASE})

# Folders files
set(CPP_DIR_1 ../../source/extensions/python/Modules)
set(CPP_DIR_2 ../../source/extensions/python/Modules/cjkcodecs)
set(CPP_DIR_3 ../../source/extensions/python/Modules/zlib)
set(CPP_DIR_4 ../../source/extensions/python/Modules/_ctypes)
set(CPP_DIR_5 ../../source/extensions/python/Modules/_ctypes/libffi_msvc)
set(CPP_DIR_6 ../../source/extensions/python/Modules/_io)
set(CPP_DIR_7 ../../source/extensions/python/Modules/_multiprocessing)
set(CPP_DIR_8 ../../source/extensions/python/Objects)
set(CPP_DIR_9 ../../source/extensions/python/Parser)
set(CPP_DIR_10 ../../source/extensions/python/PC)
set(CPP_DIR_11 ../../source/extensions/python/Python)
set(CPP_DIR_12 ../../source/extensions/python)
set(HEADER_DIR_1 ../../source/extensions/python/Include)
set(HEADER_DIR_2 ../../source/extensions/python/Modules/cjkcodecs)
set(HEADER_DIR_3 ../../source/extensions/python/Modules)
set(HEADER_DIR_4 ../../source/extensions/python/Modules/zlib)
set(HEADER_DIR_5 ../../source/extensions/python/Modules/_io)
set(HEADER_DIR_6 ../../source/extensions/python/Modules/_multiprocessing)
set(HEADER_DIR_7 ../../source/extensions/python/Objects/stringlib)
set(HEADER_DIR_8 ../../source/extensions/python/Objects)
set(HEADER_DIR_9 ../../source/extensions/python/Parser)
set(HEADER_DIR_10 ../../source/extensions/python/PC)
set(HEADER_DIR_11 ../../source/extensions/python/Python)
set(HEADER_DIR_12 ../../source/extensions/python)
set(HEADER_DIR_13 ../../source/ReflectiveDLLInjection/common)
set(HEADER_DIR_14 ../../source/extra_includes)


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
   -DHAVE_RAND_EGD 
   -DNDEBUG 
   -D_WINDOWS 
   -D_USRDLL 
   -DEXT_SERVER_PYTHON_EXPORTS 
   -DPy_BUILD_CORE 
   -DPy_ENABLE_SHARED 
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
    add_subdirectory(../backcompat ${OUTPUT_RELEASE})
   add_subdirectory(../common ${OUTPUT_RELEASE})
   add_subdirectory(../ReflectiveDLLInjection ${OUTPUT_RELEASE})
   add_subdirectory(../metsrv ${OUTPUT_RELEASE})
else()
   add_subdirectory(../metsrv ${OUTPUT_RELEASE})
   link_directories(${OUTPUT_RELEASE})
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
   set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /W3 /EHsc")
   set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /W3 /EHsc")
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
    ${CPP_DIR_2}/*.c
    ${CPP_DIR_3}/*.c
    ${CPP_DIR_4}/*.c
    ${CPP_DIR_5}/*.c
    ${CPP_DIR_6}/*.c
    ${CPP_DIR_7}/*.c
    ${CPP_DIR_8}/*.c
    ${CPP_DIR_9}/*.c
    ${CPP_DIR_10}/*.c
    ${CPP_DIR_11}/*.c
    ${CPP_DIR_12}/*.c
    ${HEADER_DIR_1}/*.h
    ${HEADER_DIR_2}/*.h
    ${HEADER_DIR_3}/*.h
    ${HEADER_DIR_4}/*.h
    ${HEADER_DIR_5}/*.h
    ${HEADER_DIR_6}/*.h
    ${HEADER_DIR_7}/*.h
    ${HEADER_DIR_8}/*.h
    ${HEADER_DIR_9}/*.h
    ${HEADER_DIR_10}/*.h
    ${HEADER_DIR_11}/*.h
    ${HEADER_DIR_12}/*.h
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

# Add library to build.
add_library(${PROJECT_NAME} SHARED
   ${SRC_FILES}
)

# Link with other dependencies.
#target_link_libraries(${PROJECT_NAME} backcompat common metsrv ReflectiveDLLInjection )
target_link_libraries(${PROJECT_NAME} common metsrv ReflectiveDLLInjection ssleay32 libeay32 gdiplus netapi32 crypt32 ws2_32 mpr)
if(MSVC)
   target_link_libraries(${PROJECT_NAME} ssleay32.lib libeay32.lib gdiplus.lib backcompat.lib Netapi32.lib crypt32.lib ws2_32.lib Mpr.lib metsrv.lib )
endif(MSVC)
