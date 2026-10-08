#include "precomp.h"
#include "common_metapi.h"

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
	Packet *response = met_api->packet.create_response(packet);

	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;

	do
	{
		// Preserve the previous ERROR_NOT_SUPPORTED result if the optional export is absent.
		met_api->win_api.kernel32.SetLastError(ERROR_NOT_SUPPORTED);
		if (!met_api->win_api.winhttp.WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
			dwResult = met_api->win_api.kernel32.GetLastError();
			dprintf("[PROXY] Failed to extract proxy configuration. error=%d (0x%x)", dwResult, (ULONG_PTR)dwResult);
			break;
		}

		met_api->packet.add_tlv_bool(response, TLV_TYPE_PROXY_CFG_AUTODETECT, proxyConfig.fAutoDetect);

		if (proxyConfig.lpszAutoConfigUrl) {
			met_api->packet.add_tlv_wstring(response, TLV_TYPE_PROXY_CFG_AUTOCONFIGURL, proxyConfig.lpszAutoConfigUrl);
			met_api->win_api.kernel32.GlobalFree((HGLOBAL)proxyConfig.lpszAutoConfigUrl);
		}

		if (proxyConfig.lpszProxy) {
			met_api->packet.add_tlv_wstring(response, TLV_TYPE_PROXY_CFG_PROXY, proxyConfig.lpszProxy);
			met_api->win_api.kernel32.GlobalFree((HGLOBAL)proxyConfig.lpszProxy);
		}

		if (proxyConfig.lpszProxyBypass) {
			met_api->packet.add_tlv_wstring(response, TLV_TYPE_PROXY_CFG_PROXYBYPASS, proxyConfig.lpszProxyBypass);
			met_api->win_api.kernel32.GlobalFree((HGLOBAL)proxyConfig.lpszProxyBypass);
		}

		dwResult = ERROR_SUCCESS;

	} while(0);

	met_api->packet.transmit_response(dwResult, remote, response);

	return dwResult;
}
