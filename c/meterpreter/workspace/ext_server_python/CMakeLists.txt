set(PROJECT_NAME ext_server_python)

project(${PROJECT_NAME} C)

if(MSVC)
    enable_language(ASM_MASM)
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/../CMakeListsFuncs.txt)

add_definitions(
    -D_USRDLL
    -DPy_ENABLE_SHARED
    -DPy_BUILD_CORE
    -D_CRT_SECURE_NO_WARNINGS
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MP")

include_directories(../../source/common)
include_directories(../../source/ReflectiveDllInjection/common)
include_directories(../../source/extensions/python/include)
include_directories(../../source/extensions/python/Modules/_ctypes/libffi_msvc)
include_directories(../../source/extensions/python/Modules/zlib)
include_directories(../../source/extensions/python/PC)
include_directories(../../source/extensions/python/Python)
include_directories(../../deps/libressl/include)

set(SRC_DIR ../../source/extensions/python)
file(GLOB_RECURSE SRC_FILES
    ${SRC_DIR}/*.c
    ${SRC_DIR}/*.rc
    ${MOD_DEF_DIR}/extension.def
)

if(IS_X64)
    set(SRC_FILES ${SRC_FILES} ${SRC_DIR}/Modules/_ctypes/libffi_msvc/win64.asm)
    list(REMOVE_ITEM SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${SRC_DIR}/Modules/_ctypes/libffi_msvc/win32.c)
endif()

add_library(${PROJECT_NAME} SHARED ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.${TARGET_ARCH})
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/DEF:\"${MOD_DEF_DIR}/extension.def\"")
set_source_files_properties(${MOD_DEF_DIR}/extension.def PROPERTIES HEADER_FILE_ONLY TRUE)

set(LIBRESSL_LIB_DIR ${WORKSPACE_ROOT_DIR}/../deps/libressl/output/${CMAKE_GENERATOR_TOOLSET}/${TARGET_ARCH})

set(LINK_LIBS ws2_32 crypt32)

# Add the libressl deps
set(LINK_LIBS
    ${LINK_LIBS}
    ${LIBRESSL_LIB_DIR}/crypto-46.lib
    ${LIBRESSL_LIB_DIR}/ssl-48.lib
    ${LIBRESSL_LIB_DIR}/tls-20.lib
)

target_link_libraries(${PROJECT_NAME} ${LINK_LIBS} ${MET_RDI_ASM})
if(MSVC)
    target_link_options(${PROJECT_NAME} PUBLIC "/ignore:4070")
endif()

# Post processing (required for all Meterpreter DLLs)
editbin(${PROJECT_NAME} ${BIN_SUBSYSTEM})
copyoutput(${PROJECT_NAME} ${BIN_OUTPUT_DIR})
