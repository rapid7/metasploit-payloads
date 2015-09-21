/*!
 * @file wmi.h
 * @brief Declarations for PAGEANTJACKER request handlers.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_EXTAPI_PAGEANTJACKER_H
#define _METERPRETER_SOURCE_EXTENSION_EXTAPI_PAGEANTJACKER_H

#include "../../common/common.h"

DWORD request_pageant_send_query(Remote *remote, Packet *packet);

#endif
