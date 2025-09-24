package com.metasploit.meterpreter.stdapi;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.metasploit.TLVPacket;
import com.metasploit.TLVType;

public class stdapi_net_config_get_interfaces_V1_6 extends stdapi_net_config_get_interfaces_V1_4 {

    @Override
    public Address[] getAddresses(NetworkInterface iface) throws IOException {
        List/* <Address> */result = new ArrayList();
        List addresses = iface.getInterfaceAddresses();
        for (Iterator it = addresses.iterator(); it.hasNext(); ) {
            InterfaceAddress addr = (InterfaceAddress) it.next();
            byte[] ip = addr.getAddress().getAddress();
            if (ip == null) {
                continue;
            }
            int prefixLength = addr.getNetworkPrefixLength();
            if (prefixLength == -1 && ip.length == 4) {
                // guess netmask by network class...
                if ((ip[0] & 0xff) < 0x80) {
                    prefixLength = 8;
                } else if ((ip[0] & 0xff) < 0xc0) {
                    prefixLength = 16;
                } else {
                    prefixLength = 24;
                }
            }
            byte[] scopeId = null;
            if (addr.getAddress() instanceof Inet6Address) {
                ByteBuffer bb = ByteBuffer.allocate(4);
                bb.order(ByteOrder.BIG_ENDIAN);
                bb.putInt(((Inet6Address) addr.getAddress()).getScopeId());
                scopeId = bb.array();
            }
            result.add(new Address(ip, prefixLength, scopeId));
        }
        return (Address[]) result.toArray(new Address[0]);
    }

    @Override
    protected void addMTU(TLVPacket ifaceTLV, NetworkInterface iface) throws IOException {
        ifaceTLV.add(TLVType.TLV_TYPE_MTU, iface.getMTU());
    }
}
