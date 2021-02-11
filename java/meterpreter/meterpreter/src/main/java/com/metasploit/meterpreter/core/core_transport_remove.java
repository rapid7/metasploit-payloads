package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.Transport;
import com.metasploit.meterpreter.command.Command;

public class core_transport_remove implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        Transport t = meterpreter.getTransports().current();

        // check if this is the last transport
        if (t == t.getNext()) {
            // cant' delete the last transport
            return ERROR_FAILURE;
        }

        String transportUrl = request.getStringValue(TLVType.TLV_TYPE_TRANS_URL);
        Transport found = null;

        do {
            if (t.getUrl().equals(transportUrl)) {
                found = t;
                break;
            }
            t = t.getNext();
        } while(t != meterpreter.getTransports().current());

        if (found == null || found == meterpreter.getTransports().current()) {
            // invalid transport specified (missing or current)
            return ERROR_FAILURE;
        }

        meterpreter.getTransports().remove(found);

        return ERROR_SUCCESS;
    }
}


