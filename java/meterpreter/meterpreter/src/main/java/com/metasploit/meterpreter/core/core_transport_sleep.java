package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.Transport;
import com.metasploit.meterpreter.command.Command;

public class core_transport_sleep implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        int result = EXIT_DISPATCH;

        try {
            long sleep = request.getIntValue(TLVType.TLV_TYPE_TRANS_COMM_TIMEOUT) * Transport.MS;
            meterpreter.getTransports().setNext(meterpreter.getTransports().current(), sleep);
        }
        catch (Exception ex) {
            result = ERROR_FAILURE;
        }

        return result;
    }
}

