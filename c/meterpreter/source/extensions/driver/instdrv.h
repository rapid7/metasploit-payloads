/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015, portions (C) Mark Russinovich, FileMon
*
*  TITLE:       INSTDRV.H
*
*  VERSION:     1.10
*
*  DATE:        10 Mar 2015
*
*  Common header file for the program SCM usage.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

BOOL scmInstallDriver(
	_In_ SC_HANDLE SchSCManager,
	_In_ LPCTSTR DriverName,
	_In_opt_ LPCTSTR ServiceExe
	);

BOOL scmStartDriver(
	_In_ SC_HANDLE SchSCManager,
	_In_ LPCTSTR DriverName
	);

BOOL scmOpenDevice(
	_In_ LPCTSTR DriverName,
	_Inout_opt_ PHANDLE lphDevice
	);

BOOL scmStopDriver(
	_In_ SC_HANDLE SchSCManager,
	_In_ LPCTSTR DriverName
	);

BOOL scmRemoveDriver(
	_In_ SC_HANDLE SchSCManager,
	_In_ LPCTSTR DriverName
	);

BOOL scmUnloadDeviceDriver(
	_In_ LPCTSTR Name
	);

BOOL scmLoadDeviceDriver(
	_In_		LPCTSTR Name,
	_In_opt_	LPCTSTR Path,
	_Inout_		PHANDLE lphDevice
	);
