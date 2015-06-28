package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.Transport;
import com.metasploit.meterpreter.TcpTransport;
import com.metasploit.meterpreter.HttpTransport;
import com.metasploit.meterpreter.Utils;
import com.metasploit.meterpreter.command.Command;

public class core_transport_change extends core_transport_add {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        int result = super.execute(meterpreter, request, response);

        if (result == ERROR_SUCCESS) {
            // transport added as a previous element, switch it
            meterpreter.getTransports().setNext(meterpreter.getTransports().current().getPrev(), 0);
            result = EXIT_DISPATCH;
        }

        return result;
    }
}

