/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       CUI.H
*
*  VERSION:     1.00
*
*  DATE:        18 Jan 2016
*
*  Common header file for console ui.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include "drivertools.h"

VOID tdlError(
	_In_ Remote *remote,
	_In_ Packet *request,
	_In_ LPWSTR lpText
	);

VOID tdlWarning(
	_In_ Remote *remote,
	_In_ Packet *request,
	_In_ LPWSTR lpText
	);

VOID tdlSuccess(
	_In_ Remote *remote,
	_In_ Packet *request,
	_In_ LPWSTR lpText
	);

VOID tdlPrintClient(
	_In_ Remote *remote,
	_In_ Packet *request,
	_In_ LPWSTR lpText
	);