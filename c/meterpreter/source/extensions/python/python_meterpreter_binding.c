/*!
 * @file python_meterpreter_binding.c
 * @brief Definitions for functions that support meterpreter bindings.
 */
#include "../../common/common.h"
#include "Python.h"

static Remote* gRemote = NULL;
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
	packet.header = *(TlvHeader*)packetBytes;
	packet.payload = (PUCHAR)(packetBytes + sizeof(TlvHeader));
	packet.payloadLength = (ULONG)packetLength - sizeof(TlvHeader);


	// If the functionality doesn't require interaction with MSF, then
	// make the packet as local so that the packet receives the request
	// and so that the packet doesn't get sent to Meterpreter
	packet.local = isLocal;

	DWORD result = command_handle(gRemote, &packet);

	// really not sure how to deal with the non-local responses at this point.

	return result == ERROR_SUCCESS ? Py_True : Py_False;
}

VOID binding_insert_command(const char* commandName)
{
	static PyMethodDef def;
	dprintf("[PYTHON] inserting command %s", commandName);
	def.ml_name = commandName;
	def.ml_meth = binding_invoke;
	def.ml_flags = METH_VARARGS;
	def.ml_doc = NULL;

	PyObject* fun = PyCFunction_New(&def, gMeterpreterModule);
	PyModule_AddObject(gMeterpreterModule, commandName, fun);
}

VOID binding_startup(Remote* remote)
{
	if (gBoundCommandList == NULL)
	{
		gBoundCommandList = list_create();
	}

	gRemote = remote;
}

VOID binding_add_command(const char* commandName)
{
	dprintf("[PYTHON] Adding command %s", (char*)commandName);
	list_add(gBoundCommandList, (char*)commandName);
	binding_insert_command(commandName);
}

VOID binding_init()
{
	dprintf("[PYTHON] Initialising binding...");
	gMeterpreterModule = Py_InitModule("meterpreter_bindings", NULL);

	for (PNODE node = gBoundCommandList->start; node != NULL; node = node->next)
	{
		binding_insert_command((const char*)node->data);
	}
}