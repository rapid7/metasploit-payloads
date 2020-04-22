set(PROJECT_NAME ext_server_unhook)

project(${PROJECT_NAME} C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../CMakeListsFuncs.txt)

add_definitions(
    -D_USRDLL
)

include_directories(../../source/common)
include_directories(../../source/ReflectiveDllInjection/common)

set(SRC_DIR ../../source/extensions/unhook)
file(GLOB SRC_FILES
    ${SRC_DIR}/*.c
)
add_library(${PROJECT_NAME} SHARED ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.${TARGET_ARCH})

if(IS_X86)
    set(LINK_LIBS ${LINK_LIBS} backcompat)
endif()
target_link_libraries(${PROJECT_NAME} ${LINK_LIBS})

# Post processing (required for all Meterpreter DLLs)
editbin(${PROJECT_NAME} ${BIN_SUBSYSTEM})
copyoutput(${PROJECT_NAME} ${BIN_OUTPUT_DIR})
