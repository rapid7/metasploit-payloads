#define WM_INPUT                    0x00FF
#define RID_INPUT               0x10000003
#define RID_HEADER              0x10000005

/*
* Type of the raw input
*/
#define RIM_TYPEMOUSE       0
#define RIM_TYPEKEYBOARD    1
#define RIM_TYPEHID         2

#define RIDEV_INPUTSINK         0x00000100
#define RI_KEY_E0	2
#define RI_KEY_E1	4

/*
* Raw Input Messages.
*/
typedef UINT(WINAPI *f_GetRawInputData)(
	HRAWINPUT hRawInput,
	UINT uiCommand,
	LPVOID pData,
	PUINT pcbSize,
	UINT cbSizeHeader);

typedef BOOL(WINAPI *f_RegisterRawInputDevices)(
	PCRAWINPUTDEVICE pRawInputDevices,
	UINT uiNumDevices,
	UINT cbSize);

typedef DWORD(WINAPI *f_QueryFullProcessImageNameW) (HANDLE, DWORD, LPTSTR, PDWORD);
typedef DWORD(WINAPI *f_GetProcessImageFileNameW) (HANDLE, LPTSTR, DWORD);
