#include "precomp.h"
#include "common_metapi.h"

/*
 * Opens a event log and returns the associated HANDLE to the caller if the
 * operation succeeds.
 *
 * I should add support for the UNCServerName someday...
 *
 * TLVs:
 *
 * req: TLV_TYPE_EVENT_SOURCENAME   - The event log name
 */
DWORD request_sys_eventlog_open(Remote * remote, Packet * packet)
{
	Packet * response = met_api->packet.create_response(packet);
	LPCTSTR sourceName = NULL;
	DWORD result = ERROR_SUCCESS;
	HANDLE hEvent;

	sourceName = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_EVENT_SOURCENAME);

	if(!sourceName) {
		result = ERROR_INVALID_PARAMETER;
	}
	else {
		hEvent = OpenEventLog(NULL, sourceName);
		if(!hEvent) {
			result = GetLastError();
		}
		else {
			met_api->packet.add_tlv_qword(response, TLV_TYPE_EVENT_HANDLE, (QWORD)hEvent);
		}
	}

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Returns the number of event records in an event log
 *
 * TLVs:
 *
 * req: TLV_TYPE_EVENT_HANDLE   - The event log handle
 */
DWORD request_sys_eventlog_numrecords(Remote * remote, Packet * packet)
{
	Packet * response = met_api->packet.create_response(packet);
	HANDLE hEvent = NULL;
	DWORD numRecords;
	DWORD result = ERROR_SUCCESS;

	hEvent = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_EVENT_HANDLE);

	if(!hEvent) {
		result = ERROR_INVALID_PARAMETER;
	}
	else {
		if(GetNumberOfEventLogRecords(hEvent, &numRecords) == 0) {
			result = GetLastError();
		}
		else {
			met_api->packet.add_tlv_uint(response, TLV_TYPE_EVENT_NUMRECORDS, numRecords);
		}
	}

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Reads one record from an event log
 *
 * TLVs:
 *
 * req: TLV_TYPE_EVENT_HANDLE        - The event log handle
 * req: TLV_TYPE_EVENT_READFLAGS     - The flags for the read operation
 * opt: TLV_TYPE_EVENT_RECORDOFFSET  - The record offset for SEEK operations
 */
DWORD request_sys_eventlog_read(Remote * remote, Packet * packet)
{
	Packet * response = met_api->packet.create_response(packet);
	HANDLE hEvent = NULL;
	DWORD readFlags = 0, recordOffset = 0, bytesRead, bytesNeeded;
	DWORD result = ERROR_SUCCESS;
	EVENTLOGRECORD * buf = NULL;
	BYTE * str = NULL;

	hEvent       = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_EVENT_HANDLE);
	readFlags    = (DWORD)met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_EVENT_READFLAGS);
	recordOffset = (DWORD)met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_EVENT_RECORDOFFSET);

	do {
		if(!hEvent || !readFlags) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		/* get the length of the next record, ghettoly */
		if(ReadEventLog(hEvent, readFlags, recordOffset,
		    &bytesRead, 0, &bytesRead, &bytesNeeded
		  ) != 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			result = GetLastError();
			// met_api->packet.add_raw(response, TLV_TYPE_EVENT_BYTESNEEDED)
			break;
		}

		if((buf = malloc(bytesNeeded)) == NULL) {
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		if(ReadEventLog(hEvent, readFlags, recordOffset,
		    buf, bytesNeeded, &bytesRead, &bytesNeeded
		  ) == 0) {
			result = GetLastError();
			// met_api->packet.add_raw(response, TLV_TYPE_EVENT_BYTESNEEDED)
			break;
		}

		met_api->packet.add_tlv_uint(response, TLV_TYPE_EVENT_RECORDNUMBER, buf->RecordNumber);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_EVENT_TIMEGENERATED, buf->TimeGenerated);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_EVENT_TIMEWRITTEN, buf->TimeWritten);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_EVENT_ID, buf->EventID);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_EVENT_TYPE, buf->EventType);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_EVENT_CATEGORY, buf->EventCategory);
		
		met_api->packet.add_tlv_raw(response, TLV_TYPE_EVENT_DATA, (BYTE *)buf + buf->DataOffset, buf->DataLength);

		str = (BYTE *)buf + buf->StringOffset;
		while(buf->NumStrings > 0) {
			met_api->packet.add_tlv_string(response, TLV_TYPE_EVENT_STRING, str);
			/* forward pass the null terminator */
			while(*str++ != 0);
			buf->NumStrings--;
		}

	} while(0);

	met_api->packet.transmit_response(result, remote, response);
	
	if(buf)
		free(buf);

	return ERROR_SUCCESS;
}


/*
 * Returns the record number of the oldest record (not necessarily 1).
 *
 * TLVs:
 *
 * req: TLV_TYPE_EVENT_HANDLE        - The event log handle
 */
DWORD request_sys_eventlog_oldest(Remote * remote, Packet * packet)
{
	Packet * response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	HANDLE hEvent = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_EVENT_HANDLE);
	DWORD oldest;

	if(GetOldestEventLogRecord(hEvent, &oldest) == 0) {
		result = GetLastError();
	}
	else {
		met_api->packet.add_tlv_uint(response, TLV_TYPE_EVENT_RECORDNUMBER, oldest);
	}

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Returns the record number of the oldest record (not necessarily 1).
 *
 * Should sometime support the BackupFile, but not right now..
 *
 * TLVs:
 *
 * req: TLV_TYPE_EVENT_HANDLE        - The event log handle
 */
DWORD request_sys_eventlog_clear(Remote * remote, Packet * packet)
{
	Packet * response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	HANDLE hEvent = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_EVENT_HANDLE);

	if(ClearEventLog(hEvent, NULL) == 0) {
		result = GetLastError();
	}

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Closes the specified event log.
 *
 * TLVs:
 *
 * req: TLV_TYPE_EVENT_HANDLE        - The event log handle
 */
DWORD request_sys_eventlog_close(Remote * remote, Packet * packet)
{
	Packet * response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	HANDLE hEvent = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_EVENT_HANDLE);

	if(CloseEventLog(hEvent) == 0) {
		result = GetLastError();
	}

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}