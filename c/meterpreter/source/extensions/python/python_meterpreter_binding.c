/*!
 * @file python_meterpreter_binding.c
 * @brief Definitions for functions that support meterpreter bindings.
 */
#include "common.h"
#include "common_metapi.h"
#include "python_main.h"
#include "Python.h"

static PLIST gBoundCommandList = NULL;
static PyObject* gMeterpreterModule = NULL;
static PyMethodDef* gMeterpreterMethods = NULL;
static PLIST gMeterpreterMethodDefs = NULL;

static PyObject* binding_invoke(PyObject* self, PyObject* args)
{
	dprintf("[PYTHON] a function was invoked on: %s", self->ob_type->tp_name);
	const char* packetBytes = NULL;
	BOOL isLocal = FALSE;
	Py_ssize_t packetLength = 0;

	PyArg_ParseTuple(args, "is#", &isLocal, &packetBytes, &packetLength);
	dprintf("[PYTHON] packet %p is %u bytes and is %s", packetBytes, packetLength, isLocal ? "local" : "not local");

	Packet packet = { 0 };
	packet.header = *(PacketHeader*)packetBytes;
	packet.payload = (PUCHAR)(packetBytes + sizeof(PacketHeader));
	packet.payloadLength = (ULONG)packetLength - sizeof(PacketHeader);

	// If the functionality doesn't require interaction with MSF, then
	// make the packet as local so that the packet receives the request
	// and so that the packet doesn't get sent to Meterpreter
	packet.local = isLocal;

	met_api->command.handle(gRemote, &packet);

	// really not sure how to deal with the non-local responses at this point.
	if (packet.partner == NULL)
	{
		// "None"
		return Py_BuildValue("");
	}

	PyObject* result = PyString_FromStringAndSize(packet.partner->payload, packet.partner->payloadLength);
	met_api->packet.destroy(packet.partner);
	return result;
}

VOID binding_insert_command(UINT commandId)
{
	static PyMethodDef def;
	char commandName[256] = { 0 };
	if (commandId == 0)
	{
		strncpy_s(commandName, sizeof(commandName), "meterpreter_core", sizeof(commandName) - 1);
	}
	else
	{
		sprintf_s(commandName, sizeof(commandName), "command_%u", commandId);
	}

	dprintf("[PYTHON] inserting command %s", commandName);
	def.ml_name = commandName;
	def.ml_meth = binding_invoke;
	def.ml_flags = METH_VARARGS;
	def.ml_doc = NULL;

	PyObject* fun = PyCFunction_New(&def, gMeterpreterModule);
	PyModule_AddObject(gMeterpreterModule, commandName, fun);
}

VOID binding_startup()
{
	if (gBoundCommandList == NULL)
	{
		gBoundCommandList = met_api->list.create();
	}
}

VOID binding_add_command(UINT commandId)
{
	dprintf("[PYTHON] Adding command %u", commandId);

	// We know that core commands are within the first thousand. So we can ignore anything that isn't
	// big enough here to skip out on all the core commands. It's a cheat, but it works. And we cheat
	// everywhere anyway!

	// Only add non-core commands
	if (commandId >= 1000)
	{
		met_api->list.add(gBoundCommandList, (LPVOID)(UINT_PTR)commandId);
		binding_insert_command(commandId);
	}
}

VOID binding_init()
{
	dprintf("[PYTHON] Initialising binding...");
	gMeterpreterModule = Py_InitModule("meterpreter_bindings", NULL);

	// we have a hard-coded core command binding for all core commands. This allows us to use
	// the one function for all base core commands that aren't included as part of the "normal"
	// mechanisms for extension loading. Without this, we'd have to manually wire in each of the
	// base commands, which doesn't make sense. Instead we can match against core command names
	// and funnel through this binding knowing that they'll be there regardless of the wiring.
	binding_insert_command(0);
	for (PNODE node = gBoundCommandList->start; node != NULL; node = node->next)
	{
		binding_insert_command((UINT)(UINT_PTR)node->data);
	}
}
