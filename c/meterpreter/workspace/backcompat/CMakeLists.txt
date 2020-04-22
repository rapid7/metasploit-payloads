set(PROJECT_NAME backcompat)

project(${PROJECT_NAME} C)

if(MSVC)
    enable_language(ASM_MASM)
endif()

add_definitions(
    -D_LIB
    -DUNICODE
    -D_UNICODE
)

set(SRC_DIR ../../source/backcompat)
file(GLOB SRC_FILES ${SRC_DIR}/*.asm)
set_source_files_properties(${SRC_FILES} PROPERTIES COMPILE_FLAGS "/safeseh")
add_library(${PROJECT_NAME} STATIC ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.${TARGET_ARCH})
