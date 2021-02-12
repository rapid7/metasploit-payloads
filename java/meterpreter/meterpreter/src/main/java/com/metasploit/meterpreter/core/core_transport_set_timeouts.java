package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.Transport;
import com.metasploit.meterpreter.command.Command;

public class core_transport_set_timeouts implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        Transport currentTransport = meterpreter.getTransports().current();

        try {
            long sessionExpiry = request.getIntValue(TLVType.TLV_TYPE_TRANS_SESSION_EXP);
            meterpreter.setExpiry(sessionExpiry);
        }
        catch (IllegalArgumentException ex) {
            // session expiry not specified
        }

        try {
            long commTimeout = request.getIntValue(TLVType.TLV_TYPE_TRANS_COMM_TIMEOUT);
            currentTransport.setCommTimeout(commTimeout);
        }
        catch (IllegalArgumentException ex) {
            // comm timeout not specified
        }

        try {
            long retryTotal = request.getIntValue(TLVType.TLV_TYPE_TRANS_RETRY_TOTAL);
            currentTransport.setRetryTotal(retryTotal);
        }
        catch (IllegalArgumentException ex) {
            // retry total not specified
        }

        try {
            long retryWait = request.getIntValue(TLVType.TLV_TYPE_TRANS_RETRY_WAIT);
            currentTransport.setRetryWait(retryWait);
        }
        catch (IllegalArgumentException ex) {
            // retry wait not specified
        }

        response.add(TLVType.TLV_TYPE_TRANS_SESSION_EXP, (int)meterpreter.getExpiry());
        response.add(TLVType.TLV_TYPE_TRANS_COMM_TIMEOUT, (int)currentTransport.getCommTimeout());
        response.add(TLVType.TLV_TYPE_TRANS_RETRY_TOTAL, (int)currentTransport.getRetryTotal());
        response.add(TLVType.TLV_TYPE_TRANS_RETRY_WAIT, (int)currentTransport.getRetryWait());

        return ERROR_SUCCESS;
    }
}
