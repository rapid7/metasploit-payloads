package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.net.InetAddress;
import java.util.List;
import java.util.Vector;

public class stdapi_net_resolve_hosts implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        List<String> hosts = request.getValues(TLVType.TLV_TYPE_HOST_NAME);
        int family = request.getIntValue(TLVType.TLV_TYPE_ADDR_TYPE);
        for (int i=0;i<hosts.size();i++) {
            String host = hosts.get(i);
            System.out.println(host);
            Vector<InetAddress> inetAddresses = stdapi_net_resolve_host.resolve_host(host, family);
            if (inetAddresses != null) {
                TLVPacket addrTLV = new TLVPacket();
                for(int j = 0; j < inetAddresses.size(); j++){
                    addrTLV.addOverflow(TLVType.TLV_TYPE_IP, inetAddresses.get(j).getAddress());
                    addrTLV.addOverflow(TLVType.TLV_TYPE_ADDR_TYPE, family);
                }
                response.addOverflow(TLVType.TLV_TYPE_RESOLVE_HOST_ENTRY, addrTLV);
            } else {
                response.addOverflow(TLVType.TLV_TYPE_IP, new byte[0]);
                response.addOverflow(TLVType.TLV_TYPE_ADDR_TYPE, family);
            }
        }
        return ERROR_SUCCESS;
    }
}
