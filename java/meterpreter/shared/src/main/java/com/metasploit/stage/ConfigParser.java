package com.metasploit.stage;

import java.io.UnsupportedEncodingException;

public class ConfigParser  {

    public static final int SESSION_EXPIRY_START_LEN = 12;
    public static final int UUID_LEN = 16;
    public static final int GUID_LEN = 16;
    public static final int URL_LEN = 512;

    public static final int UA_LEN = 256;
    public static final int PROXY_HOST_LEN = 128;
    public static final int PROXY_USER_LEN = 64;
    public static final int PROXY_PASS_LEN = 64;
    public static final int CERT_HASH_LEN = 20;

    public static String readString(byte[] bytes, int offset, int size) {
        byte[] bytesRead = readBytes(bytes, offset, size);
        try {
            return new String(bytesRead, "ISO-8859-1").trim();
        }
        catch (UnsupportedEncodingException ex) {
            // fallback to no encoding
            return new String(bytesRead).trim();
        }
    }

    public static byte[] readBytes(byte[] bytes, int offset, int size) {
        byte[] buf = new byte[size];
        System.arraycopy(bytes, offset, buf, 0, size);
        return buf;
    }

    public static int unpack32(byte[] bytes, int offset) {
        int res = 0;
        for (int i = 0; i < 4; i++) {
          res = res | (((int)bytes[i + offset]) & 0xFF) << (i * 8);
        }
        return res;
    }

    public static long unpack64(byte[] bytes, int offset) {
        long res = 0;
        for (int i = 0; i < 8; i++) {
          res = res | (((long)bytes[i + offset]) & 0xFF) << (i * 8);
        }
        return res;
    }
}
