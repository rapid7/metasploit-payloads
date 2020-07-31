set(PROJECT_NAME jpeg)

project(${PROJECT_NAME} C)

add_definitions(
    -D_LIB
    -D_CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /GF /Gy /TP /MP")
endif()

set(SRC_DIR ../../source/jpeg-8)
set(
    SRC_FILES
    ${SRC_DIR}/jaricom.c
    ${SRC_DIR}/jcapimin.c
    ${SRC_DIR}/jcapistd.c
    ${SRC_DIR}/jcarith.c
    ${SRC_DIR}/jccoefct.c
    ${SRC_DIR}/jccolor.c
    ${SRC_DIR}/jcdctmgr.c
    ${SRC_DIR}/jchuff.c
    ${SRC_DIR}/jcinit.c
    ${SRC_DIR}/jcmainct.c
    ${SRC_DIR}/jcmarker.c
    ${SRC_DIR}/jcmaster.c
    ${SRC_DIR}/jcomapi.c
    ${SRC_DIR}/jcparam.c
    ${SRC_DIR}/jcprepct.c
    ${SRC_DIR}/jcsample.c
    ${SRC_DIR}/jctrans.c
    ${SRC_DIR}/jdapimin.c
    ${SRC_DIR}/jdapistd.c
    ${SRC_DIR}/jdarith.c
    ${SRC_DIR}/jdatadst.c
    ${SRC_DIR}/jdatasrc.c
    ${SRC_DIR}/jdcoefct.c
    ${SRC_DIR}/jdcolor.c
    ${SRC_DIR}/jddctmgr.c
    ${SRC_DIR}/jdhuff.c
    ${SRC_DIR}/jdinput.c
    ${SRC_DIR}/jdmainct.c
    ${SRC_DIR}/jdmarker.c
    ${SRC_DIR}/jdmaster.c
    ${SRC_DIR}/jdmerge.c
    ${SRC_DIR}/jdpostct.c
    ${SRC_DIR}/jdsample.c
    ${SRC_DIR}/jdtrans.c
    ${SRC_DIR}/jerror.c
    ${SRC_DIR}/jfdctflt.c
    ${SRC_DIR}/jfdctfst.c
    ${SRC_DIR}/jfdctint.c
    ${SRC_DIR}/jidctflt.c
    ${SRC_DIR}/jidctfst.c
    ${SRC_DIR}/jidctint.c
    ${SRC_DIR}/jmemmgr.c
    ${SRC_DIR}/jmemnobs.c
    ${SRC_DIR}/jquant1.c
    ${SRC_DIR}/jquant2.c
    ${SRC_DIR}/jutils.c
)
add_library(${PROJECT_NAME} STATIC ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.${TARGET_ARCH})
