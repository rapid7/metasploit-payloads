package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.Transport;
import com.metasploit.meterpreter.HttpTransport;
import com.metasploit.meterpreter.command.Command;

public class core_transport_list implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        Transport first = meterpreter.getTransports().current();
        Transport t = first;

        // add the session expiry
        response.add(TLVType.TLV_TYPE_TRANS_SESSION_EXP, (int)meterpreter.getExpiry());

        do {
            TLVPacket transportData = new TLVPacket();

            transportData.add(TLVType.TLV_TYPE_TRANS_URL, t.getUrl());
            transportData.add(TLVType.TLV_TYPE_TRANS_COMM_TIMEOUT, (int)t.getCommTimeout());
            transportData.add(TLVType.TLV_TYPE_TRANS_RETRY_TOTAL, (int)t.getRetryTotal());
            transportData.add(TLVType.TLV_TYPE_TRANS_RETRY_WAIT, (int)t.getRetryWait());

            if (t instanceof HttpTransport) {
                HttpTransport h = (HttpTransport)t;

                if (h.getUserAgent().length() > 0) {
                    transportData.add(TLVType.TLV_TYPE_TRANS_UA, h.getUserAgent());
                }

                if (h.getProxy().length() > 0) {
                    transportData.add(TLVType.TLV_TYPE_TRANS_PROXY_HOST, h.getProxy());
                }

                if (h.getProxyUser().length() > 0) {
                    transportData.add(TLVType.TLV_TYPE_TRANS_PROXY_USER, h.getProxyUser());
                }

                if (h.getProxyPass().length() > 0) {
                    transportData.add(TLVType.TLV_TYPE_TRANS_PROXY_PASS, h.getProxyPass());
                }

                if (h.getCertHash() != null) {
                    transportData.add(TLVType.TLV_TYPE_TRANS_CERT_HASH, h.getCertHash());
                }

                if (h.getCustomHeaders() != null) {
                    transportData.add(TLVType.TLV_TYPE_TRANS_HEADERS, h.getCustomHeaders());
                }
            }

            response.addOverflow(TLVType.TLV_TYPE_TRANS_GROUP, transportData);

            t = t.getNext();
        } while (t != first);

        return ERROR_SUCCESS;
    }
}

