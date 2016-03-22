/*!
 * @file powershell_bindings.cpp
 * @brief Wrapper functions for bridging native meterp calls to powershell
 */
extern "C" {
#include "../../common/common.h"
#include "powershell_bindings.h"
}

Remote* gRemote = NULL;

VOID MeterpreterInvoke(unsigned int isLocal, unsigned char* input, unsigned int inputLength, unsigned char** output, unsigned int* outputLength)
{
	dprintf("[PSH BINDING] Input %p of %d bytes received", input, inputLength);
	/*
	dprintf("[PYTHON] a function was invoked on: %s", self->ob_type->tp_name);
	const char* packetBytes = NULL;
	BOOL isLocal = FALSE;
	Py_ssize_t packetLength = 0;

	PyArg_ParseTuple(args, "is#", &isLocal, &packetBytes, &packetLength);
	dprintf("[PYTHON] packet %p is %u bytes and is %s", packetBytes, packetLength, isLocal ? "local" : "not local");

	Packet packet = { 0 };
	packet.header = *(PacketHeader*)packetBytes;
	packet.payload = (PUCHAR)(packetBytes + sizeof(PacketHeader));
	packet.payloadLength = (ULONG)packetLength - sizeof(TlvHeader);

	// If the functionality doesn't require interaction with MSF, then
	// make the packet as local so that the packet receives the request
	// and so that the packet doesn't get sent to Meterpreter
	packet.local = isLocal;

	command_handle(gRemote, &packet);

	// really not sure how to deal with the non-local responses at this point.
	if (packet.partner == NULL)
	{
		// "None"
		return Py_BuildValue("");
	}

	PyObject* result = PyString_FromStringAndSize(packet.partner->payload, packet.partner->payloadLength);
	packet_destroy(packet.partner);
	return result;
*/
}