set(PROJECT_NAME metsrv)

project(${PROJECT_NAME} C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../CMakeListsFuncs.txt)

add_definitions(
    -D_USRDLL
    -DUNICODE
    -D_UNICODE
)

include_directories(../../source/common)
include_directories(../../source/ReflectiveDllInjection/common)

set(SRC_DIR ../../source/metsrv)
file(GLOB SRC_FILES
    ${SRC_DIR}/*.c
    ../../source/ReflectiveDllInjection/inject/src/*.c
)
add_library(${PROJECT_NAME} SHARED ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.${TARGET_ARCH})

set(LINK_LIBS winhttp wininet crypt32)
if(IS_X86)
    set(LINK_LIBS ${LINK_LIBS} backcompat)
endif()
target_link_libraries(${PROJECT_NAME} ${LINK_LIBS})

# Post processing (required for all Meterpreter DLLs)
editbin(${PROJECT_NAME} ${BIN_SUBSYSTEM})
copyoutput(${PROJECT_NAME} ${BIN_OUTPUT_DIR})
