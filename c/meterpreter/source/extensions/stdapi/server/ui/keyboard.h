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

#ifndef __MINGW32__

DECLARE_HANDLE(HRAWINPUT);

/*
* Raw format of the mouse input
*/

typedef struct tagRAWMOUSE {
	/*
	* Indicator flags.
	*/
	USHORT usFlags;

	/*
	* The transition state of the mouse buttons.
	*/
	union {
		ULONG ulButtons;
		struct  {
			USHORT  usButtonFlags;
			USHORT  usButtonData;
		};
	};


	/*
	* The raw state of the mouse buttons.
	*/
	ULONG ulRawButtons;

	/*
	* The signed relative or absolute motion in the X direction.
	*/
	LONG lLastX;

	/*
	* The signed relative or absolute motion in the Y direction.
	*/
	LONG lLastY;

	/*
	* Device-specific additional information for the event.
	*/
	ULONG ulExtraInformation;

} RAWMOUSE, *PRAWMOUSE, *LPRAWMOUSE;

/*
* Raw format of the keyboard input
*/
typedef struct tagRAWKEYBOARD {
	/*
	* The "make" scan code (key depression).
	*/
	USHORT MakeCode;

	/*
	* The flags field indicates a "break" (key release) and other
	* miscellaneous scan code information defined in ntddkbd.h.
	*/
	USHORT Flags;

	USHORT Reserved;

	/*
	* Windows message compatible information
	*/
	USHORT VKey;
	UINT   Message;

	/*
	* Device-specific additional information for the event.
	*/
	ULONG ExtraInformation;


} RAWKEYBOARD, *PRAWKEYBOARD, *LPRAWKEYBOARD;


/*
* Raw format of the input from Human Input Devices
*/
typedef struct tagRAWHID {
	DWORD dwSizeHid;    // byte size of each report
	DWORD dwCount;      // number of input packed
	BYTE bRawData[1];
} RAWHID, *PRAWHID, *LPRAWHID;

/*
* RAWINPUTDEVICE data structure.
*/
typedef struct tagRAWINPUTDEVICE {
	USHORT usUsagePage; // Toplevel collection UsagePage
	USHORT usUsage;     // Toplevel collection Usage
	DWORD dwFlags;
	HWND hwndTarget;    // Target hwnd. NULL = follows keyboard focus
} RAWINPUTDEVICE, *PRAWINPUTDEVICE, *LPRAWINPUTDEVICE;

typedef CONST RAWINPUTDEVICE* PCRAWINPUTDEVICE;

/*
* Raw Input data header
*/
typedef struct tagRAWINPUTHEADER {
	DWORD dwType;
	DWORD dwSize;
	HANDLE hDevice;
	WPARAM wParam;
} RAWINPUTHEADER, *PRAWINPUTHEADER, *LPRAWINPUTHEADER;

/*
* RAWINPUT data structure.
*/
typedef struct tagRAWINPUT {
	RAWINPUTHEADER header;
	union {
		RAWMOUSE    mouse;
		RAWKEYBOARD keyboard;
		RAWHID      hid;
	} data;
} RAWINPUT, *PRAWINPUT, *LPRAWINPUT;

#endif

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
