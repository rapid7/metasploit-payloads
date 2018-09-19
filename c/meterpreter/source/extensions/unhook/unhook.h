/*!
 * @file bare.h
 * @brief Entry point and intialisation declrations for the bare extention.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_UNHOOK_UNHOOK_H
#define _METERPRETER_SOURCE_EXTENSION_UNHOOK_UNHOOK_H

#define TLV_TYPE_EXTENSION_UNHOOK	0

// Custom TLVs go here
#define TLV_TYPE_UNHOOK_RESPONSE MAKE_CUSTOM_TLV(TLV_META_TYPE_UINT, TLV_TYPE_EXTENSION_UNHOOK,	TLV_EXTENSIONS + 1)

#endif
