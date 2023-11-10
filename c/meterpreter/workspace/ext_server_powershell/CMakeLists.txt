set(PROJECT_NAME ext_server_powershell)

project(${PROJECT_NAME} C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../CMakeListsFuncs.txt)

add_definitions(
    -D_USRDLL
    -DUNICODE
    -D_UNICODE
)

include_directories(../../source/common)
include_directories(../../source/ReflectiveDllInjection/common)

set(SRC_DIR ../../source/extensions/powershell)
file(GLOB SRC_FILES
    ${SRC_DIR}/*.c
    ${SRC_DIR}/*.cpp
    ${MOD_DEF_DIR}/extension.def
)
add_library(${PROJECT_NAME} SHARED ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.${TARGET_ARCH})
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/DEF:\"${MOD_DEF_DIR}/extension.def\"")
set_source_files_properties(${MOD_DEF_DIR}/extension.def PROPERTIES HEADER_FILE_ONLY TRUE)

set(LINK_LIBS psapi ws2_32)
target_link_libraries(${PROJECT_NAME} ${LINK_LIBS} ${MET_RDI_ASM})
if(MSVC)
    target_link_options(${PROJECT_NAME} PUBLIC "/ignore:4070")
endif()

# Post processing (required for all Meterpreter DLLs)
editbin(${PROJECT_NAME} ${BIN_SUBSYSTEM})
copyoutput(${PROJECT_NAME} ${BIN_OUTPUT_DIR})
