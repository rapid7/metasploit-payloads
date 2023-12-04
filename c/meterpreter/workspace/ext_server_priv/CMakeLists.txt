set(PROJECT_NAME ext_server_priv)

project(${PROJECT_NAME} C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../CMakeListsFuncs.txt)

add_definitions(
    -D_USRDLL
)

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MP")
else()
    add_definitions(
        '-D_WIN32_WINNT=0x601'
        '-D__deref=SAL__deref'
        '-D__deref_opt_bcount=SAL__deref_opt_bcount'
        '-D__deref_opt_out_bcount=SAL__deref_opt_out_bcount'
        '-D__deref_opt_out_opt=SAL__deref_opt_out_opt'
        '-D__deref_out=SAL__deref_out'
        '-D__deref_out_bcount=SAL__deref_out_bcount'
        '-D__deref_out_bcount_opt=SAL__deref_out_bcount_opt'
        '-D__deref_out_bcount_full=SAL__deref_out_bcount_full'
        '-D__deref_out_ecount_full=SAL__deref_out_ecount_full'
        '-D__field_bcount=DISCARD'
        '-D__field_ecount=DISCARD'
        '-D__field_xcount=DISCARD'
        '-D__in_bcount_opt=SAL__in_bcount_opt'
        '-D__in_ecount_opt=SAL__in_ecount_opt'
        '-D__in_ecount_opt=SAL__in_ecount_opt'
        '-D__format_string=SAL__format_string'
        '-D__in_z='
        '-D__inout_bcount_opt=SAL__inout_bcount_opt'
        '-D__inout_bcount_part_opt=SAL__inout_bcount_part_opt'
        '-D__out_bcount_full_opt=SAL__out_bcount_full_opt'
        '-D__out_bcount_opt=SAL__out_bcount_opt'
        '-D__out_bcount_part_opt=SAL__out_bcount_part_opt'
        '-D__out_ecount_opt=SAL__out_ecount_opt'
        '-D__out_xcount_opt=SAL__out_bcount_opt'
        '-D__range=DISCARD2'
        '-D__reserved=SAL__reserved'
        '-D__success=DISCARD'
        '-D__FUNCTION__=""'
        '-D__struct_bcount=DISCARD'
        '-D__nullterminated=SAL__nullterminated'
        '-D__in_range=__RPC__in_range'
        '-D__callback=SAL__callback'
        '-D__deref_in_bcount_opt=SAL__deref_in_bcount_opt'
    )
endif()

include_directories(../../source/common)
include_directories(../../source/dump_sam)
include_directories(../../source/ReflectiveDLLInjection/common)
include_directories(../../source/extensions/kiwi/mimikatz/inc)
include_directories(../../source/extensions/kiwi/mimikatz/modules/rpc)
include_directories(../../workspace/ext_server_priv)

set(SRC_DIR ../../source/extensions/priv)
file(GLOB SRC_FILES
    ${SRC_DIR}/*.c
    ${SRC_DIR}/*.rc
    ${MOD_DEF_DIR}/extension.def
    ../../source/extensions/kiwi/mimikatz/modules/rpc/kull_m_rpc_ms-rprn.c
    ../../source/extensions/kiwi/mimikatz/modules/rpc/kull_m_rpc_ms-efsr_c.c
)
add_library(${PROJECT_NAME} SHARED ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.${TARGET_ARCH})
if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/DEF:\"${MOD_DEF_DIR}/extension.def\"")
    set_source_files_properties(${MOD_DEF_DIR}/extension.def PROPERTIES HEADER_FILE_ONLY TRUE)
endif()

set(LINK_LIBS psapi rpcrt4)
target_link_libraries(${PROJECT_NAME} ${LINK_LIBS} ${MET_RDI_ASM})
if(MSVC)
    target_link_options(${PROJECT_NAME} PUBLIC "/ignore:4070")
endif()

# Post processing (required for all Meterpreter DLLs)
editbin(${PROJECT_NAME} ${BIN_SUBSYSTEM})
copyoutput(${PROJECT_NAME} ${BIN_OUTPUT_DIR})
