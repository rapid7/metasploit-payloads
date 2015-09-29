/*!
 * @file python_commands.c
 * @brief Definitions for the python command bindings.
 */
#include "Python.h"
#include "python_main.h"
#include "python_commands.h"

/*!
 * @brief Execute a block of python given in a string and return the result/output.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_python_execute_string(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet* response = packet_create_response(packet);
	CHAR* pythonCode = packet_get_tlv_value_string(packet, TLV_TYPE_EXTENSION_PYTHON_STRING);

	dprintf("[PYTHON] attempting to run string: %s", pythonCode);

	PyRun_SimpleString(pythonCode);

	if (response)
	{
		packet_transmit_response(dwResult, remote, response);
	}

	return dwResult;
}