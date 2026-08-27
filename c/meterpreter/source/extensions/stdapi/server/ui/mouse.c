#include "precomp.h"
#include "common_metapi.h"
#include "ui.h"

/*
 * Enables or disables mouse input
 */
DWORD request_ui_enable_mouse(Remote *remote, Packet *request)
{
	Packet *response = met_api->packet.create_response(request);
	BOOLEAN enable = FALSE;
	DWORD result = ERROR_SUCCESS;

	enable = met_api->packet.get_tlv_value_bool(request, TLV_TYPE_BOOL);

	result = input_gate_set_mouse(enable);

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}


/*
 * Send keystrokes
 */

DWORD request_ui_send_mouse(Remote *remote, Packet *request)
{
	Packet *response = met_api->packet.create_response(request);
	DWORD result = ERROR_SUCCESS;

	DWORD action = met_api->packet.get_tlv_value_uint(request, TLV_TYPE_MOUSE_ACTION);
	DWORD x = met_api->packet.get_tlv_value_uint(request, TLV_TYPE_MOUSE_X);
	DWORD y = met_api->packet.get_tlv_value_uint(request, TLV_TYPE_MOUSE_Y);

	INPUT input = {0};
	input.type = INPUT_MOUSE;
	input.mi.mouseData = 0;
	input.mi.dwExtraInfo = input_gate_marker();
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
		double width = met_api->win_api.user32.GetSystemMetrics(SM_CXSCREEN)-1;
		double height = met_api->win_api.user32.GetSystemMetrics(SM_CYSCREEN)-1;
		double dx = x*(65535.0f / width);
		double dy = y*(65535.0f / height);
		input.mi.dx = (LONG)dx;
		input.mi.dy = (LONG)dy;
		input.mi.dwFlags |= MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;
	}
	met_api->win_api.user32.SendInput(1, &input, sizeof(INPUT));
	if (action == 1)
	{
		input.mi.dwFlags &= ~(MOUSEEVENTF_LEFTDOWN);
		input.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
		met_api->win_api.user32.SendInput(1, &input, sizeof(INPUT));
	}
	else if (action == 4)
	{
		input.mi.dwFlags &= ~(MOUSEEVENTF_RIGHTDOWN);
		input.mi.dwFlags |= MOUSEEVENTF_RIGHTUP;
		met_api->win_api.user32.SendInput(1, &input, sizeof(INPUT));
	}
	else if (action == 7)
	{
		input.mi.dwFlags &= ~(MOUSEEVENTF_LEFTDOWN);
		input.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
		met_api->win_api.user32.SendInput(1, &input, sizeof(INPUT));
		input.mi.dwFlags &= ~(MOUSEEVENTF_LEFTUP);
		input.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
		met_api->win_api.user32.SendInput(1, &input, sizeof(INPUT));
		input.mi.dwFlags &= ~(MOUSEEVENTF_LEFTDOWN);
		input.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
		met_api->win_api.user32.SendInput(1, &input, sizeof(INPUT));
	}

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}


