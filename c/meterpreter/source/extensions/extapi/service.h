/*!
 * @file service.h
 * @brief Declarations for service management functions
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_EXTAPI_SERVICE_H
#define _METERPRETER_SOURCE_EXTENSION_EXTAPI_SERVICE_H

DWORD request_service_enum(Remote *remote, Packet *packet);
DWORD request_service_query(Remote *remote, Packet *packet);

#endif
