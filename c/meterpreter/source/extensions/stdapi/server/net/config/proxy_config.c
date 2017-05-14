#include "precomp.h"

typedef struct
{
    BOOL    fAutoDetect;
    LPWSTR  lpszAutoConfigUrl;
    LPWSTR  lpszProxy;
    LPWSTR  lpszProxyBypass;
} WINHTTP_CURRENT_USER_IE_PROXY_CONFIG;

typedef BOOL (WINAPI * PWINHTTPGETIEPROXYCONFIGFORCURRENTUSER)(
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *pProxyConfig
);

/*!
 * @brief Get the current Internet Explorer proxy configuration.
 * @param remote Pointer to the \c Remote instance making the call.
 * @param packet Pointer to the \c Request packet.
 * @return Indication of success or failure.
 * @remark This function will only get the proxy configuration that is
 *         available through IE. This also happens to be the same as that
 *         which Chrome uses, so you get that for free. But other browsers
 *         such as Firefox, Safari, Opera, etc. which have their own
 *         settings are not supported by this function.
 */
DWORD request_net_config_get_proxy_config(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_NOT_SUPPORTED;
	Packet *response = packet_create_response(packet);

	HMODULE hWinHttp = NULL;
	PWINHTTPGETIEPROXYCONFIGFORCURRENTUSER pProxyFun = NULL;
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;

	do
	{
		if ((hWinHttp = LoadLibraryA("Winhttp.dll")) == NULL) {
			dprintf("[PROXY] Unable to load Winhttp.dll");
			break;
		}

		if ((pProxyFun = (PWINHTTPGETIEPROXYCONFIGFORCURRENTUSER)GetProcAddress(hWinHttp, "WinHttpGetIEProxyConfigForCurrentUser")) == NULL) {
			dprintf("[PROXY] Unable to find WinHttpGetIEProxyConfigForCurrentUser in Winhttp.dll");
			break;
		}

		if (!pProxyFun(&proxyConfig)) {
			BREAK_ON_ERROR("[PROXY] Failed to extract proxy configuration");
			break;
		}

		packet_add_tlv_bool(response, TLV_TYPE_PROXY_CFG_AUTODETECT, proxyConfig.fAutoDetect);

		if (proxyConfig.lpszAutoConfigUrl) {
			packet_add_tlv_wstring(response, TLV_TYPE_PROXY_CFG_AUTOCONFIGURL, proxyConfig.lpszAutoConfigUrl);
			GlobalFree((HGLOBAL)proxyConfig.lpszAutoConfigUrl);
		}

		if (proxyConfig.lpszProxy) {
			packet_add_tlv_wstring(response, TLV_TYPE_PROXY_CFG_PROXY, proxyConfig.lpszProxy);
			GlobalFree((HGLOBAL)proxyConfig.lpszProxy);
		}

		if (proxyConfig.lpszProxyBypass) {
			packet_add_tlv_wstring(response, TLV_TYPE_PROXY_CFG_PROXYBYPASS, proxyConfig.lpszProxyBypass);
			GlobalFree((HGLOBAL)proxyConfig.lpszProxyBypass);
		}

		dwResult = ERROR_SUCCESS;

	} while(0);

	if (hWinHttp != NULL) {
		FreeLibrary(hWinHttp);
	}

	packet_transmit_response(dwResult, remote, response);

	return dwResult;
}
