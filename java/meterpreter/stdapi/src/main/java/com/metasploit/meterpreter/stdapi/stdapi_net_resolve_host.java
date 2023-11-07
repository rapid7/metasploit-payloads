package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import java.util.List;
import java.util.ArrayList;

public class stdapi_net_resolve_host implements Command {

    private static final int AF_INET = 2;
    private static final int AF_INET6 = 23;

    public static List<InetAddress> resolve_host(String host, int family) {
        InetAddress[] inetAddresses;
        List<InetAddress> addressList = new ArrayList<InetAddress>();
        try {
            inetAddresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            return null;
        }
        for (InetAddress address : inetAddresses) {
            if (family == AF_INET6) {
                if (address instanceof Inet6Address) {
                    addressList.add(address);
                }
            } else if (family == AF_INET) {
                if (address instanceof Inet4Address) {
                    addressList.add(address);
                }
            } else {
                addressList.add(address);
            }
        }
        if (addressList.isEmpty()) {
            return null;
        } else {
            return addressList;
        }
    }

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String host = request.getStringValue(TLVType.TLV_TYPE_HOST_NAME);
        int family = request.getIntValue(TLVType.TLV_TYPE_ADDR_TYPE);
        List<InetAddress> inetAddresses = resolve_host(host, family);
        if (inetAddresses != null) {
            TLVPacket addrTLV = new TLVPacket();
            for(int i = 0; i < inetAddresses.size(); i++){
                addrTLV.addOverflow(TLVType.TLV_TYPE_IP, inetAddresses.get(i).getAddress());
                addrTLV.addOverflow(TLVType.TLV_TYPE_ADDR_TYPE, family);
            }
            response.addOverflow(TLVType.TLV_TYPE_RESOLVE_HOST_ENTRY, addrTLV);
        }
        return ERROR_SUCCESS;
    }
}
