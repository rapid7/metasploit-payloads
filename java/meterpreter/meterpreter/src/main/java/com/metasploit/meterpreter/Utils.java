package com.metasploit.meterpreter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class Utils {

    public static String runCommand(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuffer stringBuffer = new StringBuffer();
        String line;
        while ((line = br.readLine()) != null) {
            stringBuffer.append(line);
            stringBuffer.append('\n');
        }
        return stringBuffer.toString();
    }

    public static String getHostname() {
        try {
            String result = InetAddress.getLocalHost().getHostName();
            if (result != "")
                return result;
        } catch (UnknownHostException e) { }

        String host = System.getenv("COMPUTERNAME");
        if (host != null)
            return host;

        host = System.getenv("HOSTNAME");
        if (host != null)
            return host;

        return "unknown";
    }
}
