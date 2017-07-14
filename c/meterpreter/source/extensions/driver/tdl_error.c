/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       CUI.C
*
*  VERSION:     1.00
*
*  DATE:        18 Jan 2016
*
*  Console output.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "tdl_error.h"

/*
* tdlReportError
* (modified cuiPrintText from TDL)
* ( ... it was much nicer than this ... )
* Purpose:
*
* Send error message to client.
*
*/


VOID tdlReportError(
	_In_ Remote *remote,
	_In_ Packet *request,
	_In_ LPWSTR lpText
	)
{
	Packet *response = packet_create_response(request);
	DWORD   result = ERROR_SUCCESS;
	CHAR   *errbuf = NULL;

	if (lpText == NULL)
		return;

	errbuf = wchar_to_utf8(lpText);
	if (errbuf) {
		packet_add_tlv_raw(response, TLV_TYPE_TDL_ERROR_MSG, (LPVOID)errbuf, (DWORD)strlen(errbuf) + 1);
		packet_transmit_response(result, remote, response);
		RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, errbuf);
	}
	else {
		packet_add_tlv_string(response, TLV_TYPE_TDL_ERROR_MSG, "Error allocating memory for errors :/ !!");
		packet_transmit_response(result, remote, response);
	}
	free(errbuf);
}
