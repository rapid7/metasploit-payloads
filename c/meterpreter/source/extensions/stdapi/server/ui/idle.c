#include "precomp.h"
#include "common_metapi.h"

/*
#ifdef _WIN64
// sf: for the x64 build we dont need to redifine this
#else
typedef struct tagLASTINPUTINFO {
    UINT cbSize;
    DWORD dwTime;
} LASTINPUTINFO, *PLASTINPUTINFO;
#endif
*/

/*
 * Returns the number of seconds the local user has been idle
 */
DWORD request_ui_get_idle_time(Remote *remote, Packet *request)
{
	LASTINPUTINFO info;
	Packet *response = met_api->packet.create_response(request);
	DWORD result = ERROR_SUCCESS;

	do
	{
		info.cbSize = sizeof(info);

		met_api->win_api.kernel32.SetLastError(ERROR_PROC_NOT_FOUND);
		if (met_api->win_api.user32.GetLastInputInfo(&info))
			met_api->packet.add_tlv_uint(response, TLV_TYPE_IDLE_TIME,
					(met_api->win_api.kernel32.GetTickCount() - info.dwTime) / 1000);
		else
			result = met_api->win_api.kernel32.GetLastError();

	} while (0);

	// Transmit the response packet
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}
