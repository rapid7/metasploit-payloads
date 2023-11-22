package com.metasploit.meterpreter.stdapi;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.ConnectException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.UnknownHostException;

public class stdapi_channel_open_V1_15 extends stdapi_channel_open {

    // Constructing a ServerSocket directly for 0.0.0.0 will listen on both IPv4 and IPv6, which, if the operator has explicitly requested 0.0.0.0,
    // may not be desirable. Java 15 and later support explicitly specifying IPv4 using ServerSocketChannel.open(StandardProtocolFamily.INET).
    // To keep backwards-compatibility, we use reflection to call the newer version.
    protected ServerSocket getSocket(String localHost, int localPort) throws UnknownHostException, IOException {
        if (localHost.equals("0.0.0.0")) {
            try {
                Class<?> standardProtocolFamilyCls = Class.forName("java.net.StandardProtocolFamily");
                Class<?> protocolFamilyCls = Class.forName("java.net.ProtocolFamily");
                java.lang.reflect.Method getValueMethod = standardProtocolFamilyCls.getMethod("valueOf", String.class);
                Object inet = getValueMethod.invoke(null, "INET");
                Class<?> sscClazz = java.nio.channels.ServerSocketChannel.class;
                java.lang.reflect.Method method = sscClazz.getMethod("open", protocolFamilyCls);
                java.nio.channels.ServerSocketChannel server = (java.nio.channels.ServerSocketChannel)method.invoke(null, inet);
                InetAddress addr = InetAddress.getByName(localHost);
                InetSocketAddress sockAddr = new InetSocketAddress(addr, localPort);
                java.lang.reflect.Method bindMethod = sscClazz.getMethod("bind", java.net.SocketAddress.class);
                bindMethod.invoke(server, sockAddr);
                ServerSocket ss = server.socket();
                return ss;
            }
            // If reflection failed for some reason, fall back to the original implementation
            catch (IllegalAccessException e) {}
            catch (ClassNotFoundException e) {}
            catch (NoSuchMethodException e) {}
            catch (InvocationTargetException e) {}
        }
        return super.getSocket(localHost, localPort);

    }
}
