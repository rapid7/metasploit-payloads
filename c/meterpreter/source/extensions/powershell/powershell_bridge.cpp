/*!
 * @file powershell_bridge.c
 * @brief Wrapper functions for bridging native meterp calls to powershell
 */
extern "C" {
#include "../../common/common.h"
#include "powershell_bridge.h"
}

/*!
 * @brief Handle the request for powershell execution.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_powershell_execute(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet* response = packet_create_response(packet);

	if (response)
	{
		packet_transmit_response(dwResult, remote, response);
	}

	return dwResult;
}
