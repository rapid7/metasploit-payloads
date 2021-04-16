package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class stdapi_net_resolve_host implements Command {

    private static final int AF_INET = 2;
    private static final int AF_INET6 = 23;

    public static InetAddress resolve_host(String host, int family) {
        InetAddress[] inetAddresses;
        try {
            inetAddresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            return null;
        }
        for (InetAddress address : inetAddresses) {
            if (family == AF_INET6) {
                if (address instanceof Inet6Address) {
                    return address;
                }
            } else if (family == AF_INET) {
                if (address instanceof Inet4Address) {
                    return address;
                }
            } else {
                return address;
            }
        }
        return null;
    }

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String host = request.getStringValue(TLVType.TLV_TYPE_HOST_NAME);
        int family = request.getIntValue(TLVType.TLV_TYPE_ADDR_TYPE);
        InetAddress inetAddress = resolve_host(host, family);
        if (inetAddress != null) {
            response.addOverflow(TLVType.TLV_TYPE_IP, inetAddress.getAddress());
            response.addOverflow(TLVType.TLV_TYPE_ADDR_TYPE, family);
        }
        return ERROR_SUCCESS;
    }
}
