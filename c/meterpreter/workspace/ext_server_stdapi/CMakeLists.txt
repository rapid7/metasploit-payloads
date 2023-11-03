set(PROJECT_NAME ext_server_stdapi)

project(${PROJECT_NAME} C CXX)

include(${CMAKE_CURRENT_SOURCE_DIR}/../CMakeListsFuncs.txt)

add_definitions(
    -D_USRDLL
    -DCINTERFACE
    -DCOBJMACROS
    -D_CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MP")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
else()
    include_directories(../../source/mingw-include)
endif()

include_directories(../../source/common)
include_directories(../../source/jpeg-8)
include_directories(../../source/ReflectiveDLLInjection/common)
include_directories(../../source/extensions/stdapi/server)
include_directories(../../source/tiny-regex-c)

set(SRC_DIR ../../source/extensions/stdapi)
file(GLOB_RECURSE SRC_FILES
    ${SRC_DIR}/*.c
    ${SRC_DIR}/*.cpp
    ${SRC_DIR}/*.rc
    ${MOD_DEF_DIR}/extension.def
    ../../source/tiny-regex-c/*.c
)

list(REMOVE_ITEM SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${SRC_DIR}/server/resource/hook.c)

add_library(${PROJECT_NAME} SHARED ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.${TARGET_ARCH})
if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/DEF:\"${MOD_DEF_DIR}/extension.def\"")
    set_source_files_properties(${MOD_DEF_DIR}/extension.def PROPERTIES HEADER_FILE_ONLY TRUE)
endif()

set(LINK_LIBS
    jpeg
    mpr
    netapi32
    psapi
    winmm
    iphlpapi
    shlwapi
    ws2_32
    strmiids
)

if(MSVC)
    target_link_options(${PROJECT_NAME} PUBLIC "/ignore:4070")
endif()

target_link_libraries(${PROJECT_NAME} ${LINK_LIBS} ${MET_RDI_ASM})

# Post processing (required for all Meterpreter DLLs)
editbin(${PROJECT_NAME} ${BIN_SUBSYSTEM})
copyoutput(${PROJECT_NAME} ${BIN_OUTPUT_DIR})
