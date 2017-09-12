package com.metasploit.stage;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.TimeUnit;

public class ConfigParser  {

    public static final int SESSION_EXPIRY_START_LEN = 12;
    public static final int UUID_LEN = 16;
    public static final int GUID_LEN = 16;
    public static final int INT_LEN = 4;
    public static final int URL_LEN = 512;
    public static final int UA_LEN = 256;
    public static final int PROXY_HOST_LEN = 128;
    public static final int PROXY_USER_LEN = 64;
    public static final int PROXY_PASS_LEN = 64;
    public static final int CERT_HASH_LEN = 20;

    private static final long MS = TimeUnit.SECONDS.toMillis(1);

    public static Config parseConfig(byte[] configBytes) {

        Config config = new Config();
        config.rawConfig = configBytes;
        int csr = ConfigParser.SESSION_EXPIRY_START_LEN;
        config.session_expiry = MS * ConfigParser.unpack32(configBytes, csr);
        csr += INT_LEN;
        config.uuid = ConfigParser.readBytes(configBytes, csr, ConfigParser.UUID_LEN);
        csr += ConfigParser.UUID_LEN;
        config.session_guid = ConfigParser.readBytes(configBytes, csr, ConfigParser.GUID_LEN);
        csr += ConfigParser.GUID_LEN;

        while (true) {
            if (configBytes[csr] == 0) {
                break;
            }

            TransportConfig transportConfig = new TransportConfig();
            transportConfig.url = ConfigParser.readString(configBytes, csr, URL_LEN);
            csr += URL_LEN;
            transportConfig.comm_timeout = MS * ConfigParser.unpack32(configBytes, csr);
            csr += INT_LEN;
            transportConfig.retry_total = MS * ConfigParser.unpack32(configBytes, csr);
            csr += INT_LEN;
            transportConfig.retry_wait = MS * ConfigParser.unpack32(configBytes, csr);
            csr += INT_LEN;

            if (transportConfig.url.startsWith("http")) {
                transportConfig.proxy = ConfigParser.readString(configBytes, csr, ConfigParser.PROXY_HOST_LEN);
                csr += ConfigParser.PROXY_HOST_LEN;

                transportConfig.proxy_user = ConfigParser.readString(configBytes, csr, ConfigParser.PROXY_USER_LEN);
                csr += ConfigParser.PROXY_USER_LEN;

                transportConfig.proxy_pass = ConfigParser.readString(configBytes, csr, ConfigParser.PROXY_PASS_LEN);
                csr += ConfigParser.PROXY_PASS_LEN;

                transportConfig.user_agent = ConfigParser.readString(configBytes, csr, ConfigParser.UA_LEN);
                csr += ConfigParser.UA_LEN;

                transportConfig.cert_hash = null;
                byte[] loadedHash = ConfigParser.readBytes(configBytes, csr, ConfigParser.CERT_HASH_LEN);
                csr += ConfigParser.CERT_HASH_LEN;

                // we only store the cert hash value if it's got a value
                for (int i = 0; i < loadedHash.length; i++) {
                    if (loadedHash[i] != 0) {
                        transportConfig.cert_hash = loadedHash;
                        break;
                    }
                }

                String customHeaders = ConfigParser.readString(configBytes, csr);
                transportConfig.custom_headers = customHeaders;
                csr += customHeaders.length();
            }
            config.transportConfigList.add(transportConfig);
        }
        return config;
    }

    public static String readString(byte[] bytes, int offset) {
        StringBuilder stringBuffer = new StringBuilder();
        int byteEnd = bytes.length;
        for (int a=offset;a<byteEnd;a++) {
            byte byteChar = bytes[a];
            if (byteChar == 0) {
                break;
            }
            stringBuffer.append((char) (byteChar & 0xff));
        }
        return stringBuffer.toString();
    }

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
