set(PROJECT_NAME ext_server_sniffer)

project(${PROJECT_NAME} C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../CMakeListsFuncs.txt)

add_definitions(
    -D_USRDLL
    -DUNICODE
    -D_UNICODE
)

include_directories(../../source/common)
include_directories(../../source/ReflectiveDllInjection/common)
include_directories(${PSSDK_DIR}/_include)

if(${CMAKE_GENERATOR_TOOLSET} MATCHES "v120_xp")
    set(PSSDK_VER 12)
else()
    set(PSSDK_VER 19)
endif()

set(SRC_DIR ../../source/extensions/sniffer)
file(GLOB SRC_FILES
    ${SRC_DIR}/*.c
)
add_library(${PROJECT_NAME} SHARED ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.${TARGET_ARCH})

set(PSSDK_LIB_DIR ${PSSDK_DIR}/PSSDK_VC${PSSDK_VER}_LIB/_Libs)
if(IS_X64)
    set(PSSDK_LIB_DIR ${PSSDK_LIB_DIR}64)
endif()

set(LINK_LIBS ${PSSDK_LIB_DIR}/pssdk_vc${PSSDK_VER}_mt.lib ws2_32)
if(IS_X86)
    set(LINK_LIBS ${LINK_LIBS} backcompat)
endif()
target_link_libraries(${PROJECT_NAME} ${LINK_LIBS})

# Post processing (required for all Meterpreter DLLs)
editbin(${PROJECT_NAME} ${BIN_SUBSYSTEM})
copyoutput(${PROJECT_NAME} ${BIN_OUTPUT_DIR})
