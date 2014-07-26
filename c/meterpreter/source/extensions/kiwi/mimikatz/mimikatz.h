/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once

#include "globals.h"
#include "modules/kuhl_m_standard.h"
#include "modules/kuhl_m_crypto.h"
#include "modules/sekurlsa/kuhl_m_sekurlsa.h"
#include "modules/kerberos/khul_m_kerberos.h"
#include "modules/kuhl_m_service.h"
#include "modules/kuhl_m_privilege.h"
#include "modules/kuhl_m_process.h"
#include "modules/kuhl_m_lsadump.h"
#include "modules/kuhl_m_ts.h"
#include "modules/kuhl_m_event.h"
#include "modules/kuhl_m_misc.h"
#include "modules/kuhl_m_token.h"
#include "modules/kuhl_m_vault.h"
#ifdef NET_MODULE
#include "modules/kuhl_m_net.h"
#endif

#include <io.h>
#include <fcntl.h>

extern VOID (WINAPI * RtlGetNtVersionNumbers)(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);

#include "../debug.h"
