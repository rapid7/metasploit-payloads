cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

################### Variables. ####################
# Change if you want modify path or other values. #
###################################################

set(PROJECT_NAME ext_server_kiwi)
# Output Variables
set(OUTPUT_DEBUG ../../output/Debug/)
set(OUTPUT_RELEASE ../../output/Release/)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_RELEASE})
# Folders files
set(CPP_DIR_1 ../../source/extensions/kiwi)
set(CPP_DIR_2 ../../source/extensions/kiwi/mimikatz/mimikatz)
set(CPP_DIR_3 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/crypto)
set(CPP_DIR_4 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/dpapi)
set(CPP_DIR_5 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/dpapi/packages)
set(CPP_DIR_6 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/kerberos)
set(CPP_DIR_7 ../../source/extensions/kiwi/mimikatz/mimikatz/modules)
set(CPP_DIR_8 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/lsadump)
set(CPP_DIR_9 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/sekurlsa/crypto)
set(CPP_DIR_10 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/sekurlsa)
set(CPP_DIR_11 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/sekurlsa/packages)
set(CPP_DIR_12 ../../source/extensions/kiwi/mimikatz/modules)
set(CPP_DIR_13 ../../source/extensions/kiwi/mimikatz/modules/rpc)
set(HEADER_DIR_1 ../../source/extensions/kiwi)
set(HEADER_DIR_2 ../../source/extensions/kiwi/mimikatz/mimikatz)
set(HEADER_DIR_3 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/crypto)
set(HEADER_DIR_4 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/dpapi)
set(HEADER_DIR_5 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/dpapi/packages)
set(HEADER_DIR_6 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/kerberos)
set(HEADER_DIR_7 ../../source/extensions/kiwi/mimikatz/mimikatz/modules)
set(HEADER_DIR_8 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/lsadump)
set(HEADER_DIR_9 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/sekurlsa/crypto)
set(HEADER_DIR_10 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/sekurlsa)
set(HEADER_DIR_11 ../../source/extensions/kiwi/mimikatz/mimikatz/modules/sekurlsa/packages)
set(HEADER_DIR_12 ../../source/extensions/kiwi/mimikatz/modules)
set(HEADER_DIR_13 ../../source/extensions/kiwi/mimikatz/modules/rpc)
set(HEADER_DIR_14 ../../source/ReflectiveDLLInjection/common)
set(HEADER_DIR_15 ../../source/extensions/kiwi/mimikatz/inc/)
set(HEADER_DIR_16 ../../source/extra_includes)

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
   -D_WIN32_WINNT=0x0602
   -D__format_string=__format_string
   -D_POWERKATZ
   -DNDEBUG
   -D_WINDOWS
   -D_USRDLL
   -DEXT_SERVER_KIWI_EXPORTS
   -DUNICODE
   -D_UNICODE
   -D__try
   -D__in=SAL__in
   -D__in_z=SAL__in_z
   -D__deref_out_bcount_full=SAL__deref_out_bcount_full
   -D__deref=SAL__deref
   -D__out_bcount_full_opt=SAL__out_bcount_full_opt
   #-D__field_bcount\(expr\)
   -D__inout_bcount_opt=SAL__inout_bcount_opt
   -D__out_bcount_part=SAL__out_bcount_part
   -D__in_opt=SAL__in_opt
   -D__in_bcount_opt=SAL__in_bcount_opt
   -D__inout_ecount=SAL__inout_ecount
   -D__reserved=SAL__reserved
   -D__out=SAL__out
   -D__inout=SAL__inout
   -D__inout_opt=SAL__inout_opt
   -D__deref_out=SAL__deref_out
   -D__deref_out_ecount=SAL__deref_out_ecount
   -D__out_bcount=SAL__out_bcount
   -D__deref_opt_out_bcount=SAL__deref_opt_out_bcount
   -D__in_bcount=SAL__in_bcount
   -D__out_bcount_opt=SAL__out_bcount_opt
   -D__out_ecount=SAL__out_ecount
   -D__out_ecount_opt=SAL__out_ecount_opt
   -D__in_ecount=SAL__in_ecount
   -D__deref_opt_out_opt=SAL__deref_opt_out_opt
   -D__out_opt=SAL__out_opt
   -D__deref_out_bcount_opt=SAL__deref_out_bcount_opt
   -D__out_bcount_part_opt=SAL__out_bcount_part_opt
   -D__deref_out_bcount=SAL__deref_out_bcount
)

############## Artefacts Output #################
# Defines outputs , depending Debug or Release. #
#################################################

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${OUTPUT_RELEASE}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${OUTPUT_RELEASE}")
  set(CMAKE_EXECUTABLE_OUTPUT_DIRECTORY "${OUTPUT_RELEASE}")
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
#CMAKE_FORCE_C_COMPILER(clang GNU)
#CMAKE_FORCE_C_COMPILER(${GNU_HOST}-gcc GNU)
# CMake doesn't automatically look for prefixed 'windres', do it manually:
#SET(CMAKE_RC_COMPILER ${GNU_HOST}-windres)
 set( _MSC_VER 1910 )
SET(CMAKE_C_COMPILER clang)
if(MSVC)
   set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /W3 /EHsc")
   set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /W3 /Oi /EHsc")
endif(MSVC)
if(NOT MSVC)
 set(CMAKE_LIBRARY_ARCHITECTURE x64 CACHE STRING "" FORCE)
 set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -target x86_64-w64-windows-gnu -I/usr/x86_64-w64-mingw32/include/ -L/usr/lib/gcc/x86_64-w64-mingw32/8.2.0/include/ -L/usr/x86_64-w64-mingw32/lib -Wfatal-errors -fmsc-version=${_MSC_VER} -fms-extensions -fms-compatibility -fdelayed-template-parsing ")
   if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -stdlib=libc++")
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
    ${CPP_DIR_7}/kuhl_m_rpc.c
    #${CPP_DIR_7}/kuhl_m_rpc.c
    ${CPP_DIR_8}/*.c
    ${CPP_DIR_9}/*.c
    ${CPP_DIR_10}/*.c
    ${CPP_DIR_11}/*.c
    ${CPP_DIR_12}/*.c
    ${CPP_DIR_13}/*.c
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
    ${HEADER_DIR_13}/*.h
)

#CPP_DIR_7 is mimikatz/mimikatz/modules
#CPP_DIR_12 is mimikatz/modules
list(REMOVE_ITEM SRC_FILES "${CPP_DIR_7}/kuhl_m_dpapi.c")
list(REMOVE_ITEM SRC_FILES "${CPP_DIR_7}/kuhl_m_acr.c")
list(REMOVE_ITEM SRC_FILES "${CPP_DIR_7}/kuhl_m_rdm.c")
list(REMOVE_ITEM SRC_FILES "${CPP_DIR_7}/kuhl_m_sr98.c")
list(REMOVE_ITEM SRC_FILES "${CPP_DIR_12}/kull_m_acr.c")
list(REMOVE_ITEM SRC_FILES "${CPP_DIR_12}/kull_m_hid.c")
list(REMOVE_ITEM SRC_FILES "${CPP_DIR_12}/kull_m_pipe.c")
list(REMOVE_ITEM SRC_FILES "${CPP_DIR_12}/kull_m_pn532.c")
list(REMOVE_ITEM SRC_FILES "${CPP_DIR_12}/kull_m_rdm.c")

 set( CMAKE_C_COMPILE_OPTIONS_PIC "" ) # no -fPIC in windows land
# Add library to build.
add_library(${PROJECT_NAME} SHARED
   ${SRC_FILES}
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
include_directories( ${HEADER_DIR_16} )



# Link with other dependencies.
#target_link_libraries(${PROJECT_NAME} backcompat metsrv ReflectiveDLLInjection )
target_link_libraries(${PROJECT_NAME} common metsrv version ncrypt fltlib cabinet userenv winscard  crypt32 cryptdll dnsapi netapi32 ntdsapi ole32 oleaut32 rpcrt4 shlwapi samlib secur32 shell32 user32 hid setupapi wldap32 winsta psapi wtsapi32 ntdll )
if(MSVC)
   target_link_libraries(${PROJECT_NAME} version.lib ncrypt.lib fltlib.lib cabinet.lib userenv.lib Winscard.lib advapi32.lib crypt32.lib cryptdll.lib dnsapi.lib msxml2.lib netapi32.lib ntdsapi.lib ole32.lib oleaut32.lib rpcrt4.lib shlwapi.lib samlib.lib secur32.lib shell32.lib user32.lib hid.lib setupapi.lib wldap32.lib advapi32.hash.lib ntdll.min.lib msasn1.min.lib netapi32.min.lib winsta.lib backcompat.lib metsrv.lib psapi.lib advapi32.lib user32.lib secur32.lib crypt32.lib shlwapi.lib wtsapi32.lib )
endif(MSVC)
