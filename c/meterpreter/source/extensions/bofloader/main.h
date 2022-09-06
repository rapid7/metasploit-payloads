/*!
 * @file main.h
 * @brief TLV related bits for the KIWI extension.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_BOF_BOF_H
#define _METERPRETER_SOURCE_EXTENSION_BOF_BOF_H

#include "../../common/common.h"

#define TLV_TYPE_EXTENSION_BOF 0

#define TLV_TYPE_BOFLOADER_CMD_EXEC             MAKE_CUSTOM_TLV(TLV_META_TYPE_RAW,    TLV_TYPE_EXTENSION_BOF, TLV_EXTENSIONS + 100)
#define TLV_TYPE_BOFLOADER_CMD_RESULT       MAKE_CUSTOM_TLV(TLV_META_TYPE_STRING, TLV_TYPE_EXTENSION_BOF, TLV_EXTENSIONS + 101)

#endif