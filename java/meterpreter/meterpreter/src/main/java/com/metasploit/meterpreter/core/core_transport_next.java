package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.Transport;
import com.metasploit.meterpreter.TcpTransport;
import com.metasploit.meterpreter.HttpTransport;
import com.metasploit.meterpreter.Utils;
import com.metasploit.meterpreter.command.Command;

public class core_transport_next implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        meterpreter.getTransports().setNext(meterpreter.getTransports().current().getNext(), 0);

        return EXIT_DISPATCH;
    }
}

