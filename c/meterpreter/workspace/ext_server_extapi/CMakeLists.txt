set(PROJECT_NAME ext_server_extapi)

project(${PROJECT_NAME} C CXX)

include(${CMAKE_CURRENT_SOURCE_DIR}/../CMakeListsFuncs.txt)

add_definitions(
    -D_USRDLL
)

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MP")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
endif()

include_directories(../../source/common)
include_directories(../../source/ReflectiveDLLInjection/common)

set(SRC_DIR ../../source/extensions/extapi)
file(GLOB SRC_FILES
    ${SRC_DIR}/*.c
    ${SRC_DIR}/*.cpp
    ${MOD_DEF_DIR}/extension.def
)

add_library(${PROJECT_NAME} SHARED ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.${TARGET_ARCH})
if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/DEF:\"${MOD_DEF_DIR}/extension.def\"")
    set_source_files_properties(${MOD_DEF_DIR}/extension.def PROPERTIES HEADER_FILE_ONLY TRUE)
endif()

set(LINK_LIBS
    gdiplus
    ws2_32
    activeds
    wbemuuid
    esent
)

if(MSVC)
    set(LINK_LIBS ${LINK_LIBS} comsuppw)
else()
endif()

target_link_libraries(${PROJECT_NAME} ${LINK_LIBS} ${MET_RDI_ASM})
if(MSVC)
    target_link_options(${PROJECT_NAME} PUBLIC "/ignore:4070")
endif()

# Post processing (required for all Meterpreter DLLs)
editbin(${PROJECT_NAME} ${BIN_SUBSYSTEM})
copyoutput(${PROJECT_NAME} ${BIN_OUTPUT_DIR})
