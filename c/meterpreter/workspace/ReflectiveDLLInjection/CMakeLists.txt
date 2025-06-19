cmake_minimum_required(VERSION 3.15.7 FATAL_ERROR)

set(PROJECT_NAME ReflectiveDLLInjection)

project(${PROJECT_NAME} ASM)
set(ASM_SUFFIX "s")
if(MSVC)
    enable_language(ASM_MASM)
    set(ASM_SUFFIX "asm")
endif()

set(SRC_DIR ../../source/ReflectiveDLLInjection/dll/src)
if("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "x64")
    set(SRC_FILES "${SRC_DIR}/GateTrampoline64.${ASM_SUFFIX}")
elseif("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "Win32")
    set(SRC_FILES "${SRC_DIR}/GateTrampoline32.${ASM_SUFFIX}")
endif()

set_property(DIRECTORY PROPERTY COMPILE_DEFINITIONS)
set_property(DIRECTORY PROPERTY INCLUDE_DIRECTORIES)
set(CMAKE_ASM_FLAGS_RELEASE_INIT "")
set(CMAKE_ASM_FLAGS_RELEASE "")

add_library(${PROJECT_NAME} ${SRC_FILES})

if(MSVC)
    target_link_options(${PROJECT_NAME} PUBLIC "/safeseh:no")
endif()
