package com.metasploit.stage;

import java.net.URLConnection;

public class HttpConnection {

    private static boolean isEmpty(String string) {
        return (string == null || "".equals(string));
    }

    public static void addRequestHeaders(URLConnection connection, String headers, String userAgent) {
        if (!isEmpty(userAgent)) {
            connection.addRequestProperty("User-Agent", userAgent);
        }
        String[] headerPairs = headers.split("\r\n");
        for (String header : headerPairs) {
            if (isEmpty(header)) {
                continue;
            }
            String[] headerPair = header.split(": ", 2);
            if (headerPair.length == 2 && !isEmpty(headerPair[0]) && !isEmpty(headerPair[1])) {
                connection.addRequestProperty(headerPair[0], headerPair[1]);
            }
        }
    }

}
