#include "precomp.h"

extern HMODULE hookLibrary;

/*
 * Enables or disables mouse input
 */
DWORD request_ui_enable_mouse(Remote *remote, Packet *request)
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
		DWORD (*enableMouseInput)(BOOL enable) = (DWORD (*)(BOOL))GetProcAddress(
				hookLibrary, "enable_mouse_input");

		if (enableMouseInput)
			result = enableMouseInput(enable);
	}
	else
		result = GetLastError();

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}


/*
 * Send keystrokes
 */

DWORD request_ui_send_mouse(Remote *remote, Packet *request)
{
	Packet *response = packet_create_response(request);
	DWORD result = ERROR_SUCCESS;

	DWORD action = packet_get_tlv_value_uint(request, TLV_TYPE_MOUSE_ACTION);
	DWORD x = packet_get_tlv_value_uint(request, TLV_TYPE_MOUSE_X);
	DWORD y = packet_get_tlv_value_uint(request, TLV_TYPE_MOUSE_Y);

	INPUT input = {0};
	input.type = INPUT_MOUSE;
	input.mi.mouseData = 0;
	if (action == 0)
	{
		input.mi.dwFlags = MOUSEEVENTF_MOVE;
	}
	else if (action == 1)
	{
		input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
	}
	else if (action == 2)
	{
		input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
	}
	else if (action == 3)
	{
		input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
	}
	else if (action == 4)
	{
		input.mi.dwFlags = MOUSEEVENTF_RIGHTDOWN;
	}
	else if (action == 5)
	{
		input.mi.dwFlags = MOUSEEVENTF_RIGHTDOWN;
	}
	else if (action == 6)
	{
		input.mi.dwFlags = MOUSEEVENTF_RIGHTUP;
	}
	else if (action == 7)
	{
		input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
	}
	if (x != -1 || y != -1) 
	{
		double width = GetSystemMetrics(SM_CXSCREEN)-1;
		double height = GetSystemMetrics(SM_CYSCREEN)-1;
		double dx = x*(65535.0f / width);
		double dy = y*(65535.0f / height);
		input.mi.dx = (LONG)dx;
		input.mi.dy = (LONG)dy;
		input.mi.dwFlags |= MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;
	}
	SendInput(1, &input, sizeof(INPUT));
	if (action == 1)
	{
		input.mi.dwFlags &= ~(MOUSEEVENTF_LEFTDOWN);
		input.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
		SendInput(1, &input, sizeof(INPUT));
	}
	else if (action == 4)
	{
		input.mi.dwFlags &= ~(MOUSEEVENTF_RIGHTDOWN);
		input.mi.dwFlags |= MOUSEEVENTF_RIGHTUP;
		SendInput(1, &input, sizeof(INPUT));
	}
	else if (action == 7)
	{
		input.mi.dwFlags &= ~(MOUSEEVENTF_LEFTDOWN);
		input.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
		SendInput(1, &input, sizeof(INPUT));
		input.mi.dwFlags &= ~(MOUSEEVENTF_LEFTUP);
		input.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
		SendInput(1, &input, sizeof(INPUT));
		input.mi.dwFlags &= ~(MOUSEEVENTF_LEFTDOWN);
		input.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
		SendInput(1, &input, sizeof(INPUT));
	}

	// Transmit the response
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}


