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
	dprintf("[PYTHON] a function was invoked on %s", self->ob_type->tp_name);
	//packet_create(PACKET_TLV_TYPE_REQUEST, self->
	return Py_BuildValue("");
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