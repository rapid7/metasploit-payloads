set(PROJECT_NAME metsrv)

project(${PROJECT_NAME} C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../CMakeListsFuncs.txt)

add_definitions(
    -D_USRDLL
    -DUNICODE
    -D_UNICODE
    -D_CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MP")
endif()

include_directories(../../source/common)
include_directories(../../source/ReflectiveDLLInjection/common)

set(SRC_DIR ../../source/metsrv)
file(GLOB SRC_FILES
    ${SRC_DIR}/*.c
    ${MOD_DEF_DIR}/metsrv.def
)
add_library(${PROJECT_NAME} SHARED ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.${TARGET_ARCH})
if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/DEF:\"${MOD_DEF_DIR}/metsrv.def\"")
    set_source_files_properties(${MOD_DEF_DIR}/metsrv.def PROPERTIES HEADER_FILE_ONLY TRUE)
endif()

set(LINK_LIBS winhttp wininet crypt32)

if(MSVC)
    target_link_options(${PROJECT_NAME} PUBLIC "/ignore:4070")
else()
    set(LINK_LIBS ${LINK_LIBS} ws2_32)
endif()

target_link_libraries(${PROJECT_NAME} ${LINK_LIBS} ${MET_RDI_ASM})

# Post processing (required for all Meterpreter DLLs)
editbin(${PROJECT_NAME} ${BIN_SUBSYSTEM})
copyoutput(${PROJECT_NAME} ${BIN_OUTPUT_DIR})
