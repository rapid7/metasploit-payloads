cmake_minimum_required(VERSION 3.15.7 FATAL_ERROR)

set(PROJECT_NAME ReflectiveDLLInjection)

project(${PROJECT_NAME} ASM)

set(SRC_DIR ../../source/ReflectiveDLLInjection/dll/src)
if("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "(x86_64|amd64)")
  set(SRC_FILES ${SRC_DIR}/GateTrampoline64.s)
elseif("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "(i386|i686)")
  set(SRC_FILES ${SRC_DIR}/GateTrampoline32.s)
endif()

set_property(DIRECTORY PROPERTY COMPILE_DEFINITIONS)
set_property(DIRECTORY PROPERTY INCLUDE_DIRECTORIES)
set(CMAKE_ASM_FLAGS_RELEASE_INIT "")
set(CMAKE_ASM_FLAGS_RELEASE "")

add_library(${PROJECT_NAME} ${SRC_FILES})
