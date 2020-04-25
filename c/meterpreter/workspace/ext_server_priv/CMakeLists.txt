set(PROJECT_NAME ext_server_priv)

project(${PROJECT_NAME} C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../CMakeListsFuncs.txt)

add_definitions(
    -D_USRDLL
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MP")

include_directories(../../source/common)
include_directories(../../source/ReflectiveDllInjection/common)

set(SRC_DIR ../../source/extensions/priv)
file(GLOB SRC_FILES
    ${SRC_DIR}/*.c
    ../../source/ReflectiveDllInjection/inject/src/LoadLibraryR.c
)
add_library(${PROJECT_NAME} SHARED ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.${TARGET_ARCH})

set(LINK_LIBS psapi)
if(IS_X86)
    set(LINK_LIBS ${LINK_LIBS} backcompat)
endif()
target_link_libraries(${PROJECT_NAME} ${LINK_LIBS})

# Post processing (required for all Meterpreter DLLs)
editbin(${PROJECT_NAME} ${BIN_SUBSYSTEM})
copyoutput(${PROJECT_NAME} ${BIN_OUTPUT_DIR})
