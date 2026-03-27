cmake_minimum_required(VERSION 3.15.7 FATAL_ERROR)

set(PROJECT_NAME ReflectiveDLLInjection)

project(${PROJECT_NAME} ASM)
set(ASM_SUFFIX "s")
set(BITS "64")

if(MSVC)
	enable_language(ASM_MASM)
	set(ASM_SUFFIX "asm")
endif()

message(CMAKE_GENERATOR_PLATFORM="${CMAKE_GENERATOR_PLATFORM}")
set(SRC_DIR ../../source/ReflectiveDLLInjection/dll/src)
# On windows, cmake sets the CMAKE_GENERATOR_PLATFORM value to the target
# arch that we're building to, so we can rely on that. In docker, we can't
# because the value isn't set.
if(MSVC AND "${CMAKE_GENERATOR_PLATFORM}" STREQUAL "Win32")
	set(BITS "32")
elseif(NOT MSVC AND "${CMAKE_SYSTEM_PROCESSOR}" MATCHES "(i386|i686)")
	set(BITS "32")
endif()

set(SRC_FILES "${SRC_DIR}/GateTrampoline${BITS}.${ASM_SUFFIX}")

set_property(DIRECTORY PROPERTY COMPILE_DEFINITIONS)
set_property(DIRECTORY PROPERTY INCLUDE_DIRECTORIES)
set(CMAKE_ASM_FLAGS_RELEASE_INIT "")
set(CMAKE_ASM_FLAGS_RELEASE "")

add_library(${PROJECT_NAME} ${SRC_FILES})

if(MSVC)
	target_link_options(${PROJECT_NAME} PUBLIC "/safeseh:no")
endif()
