/*!
 * @file core.h
 * @brief Declarations of core components of the Meterpreter suite.
 * @details Much of what exists in the core files is used in almost every area
 *          of the Meterpreter code base, and hence it's very important. Don't
 *          change this stuff unless you know what you're doing!
 */
#ifndef _METERPRETER_METSRV_CORE_H
#define _METERPRETER_METSRV_CORE_H

#include "common_remote.h"
#include "common_list.h"

/*
 * Packet manipulation
 */
Packet* packet_create(PacketTlvType type, UINT commandId);
Packet *packet_create_response(Packet *packet);
Packet* packet_create_group();
Packet *packet_duplicate(Packet *packet);
VOID packet_destroy(Packet *packet);

DWORD packet_add_group(Packet* packet, TlvType type, Packet* groupPacket);
DWORD packet_add_tlv_string(Packet *packet, TlvType type, LPCSTR str);
DWORD packet_add_tlv_wstring(Packet *packet, TlvType type, LPCWSTR str);
DWORD packet_add_tlv_wstring_len(Packet *packet, TlvType type, LPCWSTR str, size_t strLength);
DWORD packet_add_tlv_uint(Packet *packet, TlvType type, UINT val);
DWORD packet_add_tlv_qword(Packet *packet, TlvType type, QWORD val );
DWORD packet_add_tlv_bool(Packet *packet, TlvType type, BOOL val);
DWORD packet_add_tlv_group(Packet *packet, TlvType type, Tlv *entries, DWORD numEntries);
DWORD packet_add_tlvs(Packet *packet, Tlv *entries, DWORD numEntries);
DWORD packet_add_tlv_raw(Packet *packet, TlvType type, LPVOID buf, DWORD length);
DWORD packet_is_tlv_null_terminated(Tlv *tlv);
PacketTlvType packet_get_type(Packet *packet);
TlvMetaType packet_get_tlv_meta(Packet *packet, Tlv *tlv);
DWORD packet_get_tlv(Packet *packet, TlvType type, Tlv *tlv);
DWORD packet_get_tlv_string(Packet *packet, TlvType type, Tlv *tlv);
DWORD packet_get_tlv_group_entry(Packet *packet, Tlv *group, TlvType type,Tlv *entry);
DWORD packet_enum_tlv(Packet *packet, DWORD index, TlvType type, Tlv *tlv);

BOOL packet_get_tlv_uint(Packet *packet, TlvType type, UINT* output);

LPCSTR packet_get_tlv_value_reflective_loader(Packet* packet);
PCHAR packet_get_tlv_value_string(Packet *packet, TlvType type);
wchar_t* packet_get_tlv_value_wstring(Packet* packet, TlvType type);
UINT packet_get_tlv_value_uint(Packet *packet, TlvType type);
BYTE* packet_get_tlv_value_raw(Packet* packet, TlvType type, DWORD* length);
QWORD packet_get_tlv_value_qword(Packet *packet, TlvType type);
BOOL packet_get_tlv_value_bool(Packet *packet, TlvType type);

DWORD packet_add_exception(Packet *packet, DWORD code,PCHAR string, ...);

/*
 * Packet transmission
 */
DWORD packet_transmit_response(DWORD result, Remote* remote, Packet* response);
DWORD packet_transmit(Remote* remote, Packet* packet, PacketRequestCompletion* completion);
DWORD packet_transmit_empty_response(Remote *remote, Packet *packet, DWORD res);
DWORD packet_add_request_id(Packet* packet);

/*
 * Packet completion notification
 */
DWORD packet_add_completion_handler(LPCSTR requestId, PacketRequestCompletion *completion);
DWORD packet_call_completion_handlers(Remote *remote, Packet *response,LPCSTR requestId);
DWORD packet_remove_completion_handler(LPCSTR requestId);

/*
 * Core API
 */
HANDLE core_update_thread_token( Remote *remote, HANDLE token );
VOID core_update_desktop( Remote * remote, DWORD dwSessionID, char * cpStationName, char * cpDesktopName );

#endif
