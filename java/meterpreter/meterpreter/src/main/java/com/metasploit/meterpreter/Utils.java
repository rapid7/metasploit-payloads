package com.metasploit.meterpreter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class Utils {

    public static void log(String log) {
        StackTraceElement stack = new Throwable().getStackTrace()[1];
        System.err.println("" + stack.getFileName() + ":" + stack.getLineNumber() + "=" + log);
    }

    public static String runCommand(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder stringBuilder = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            stringBuilder.append(line);
            stringBuilder.append('\n');
        }
        return stringBuilder.toString();
    }

    public static String getHostname() {
        try {
            String result = InetAddress.getLocalHost().getHostName();
            if (result.length() != 0) {
                return result;
            }
        } catch (UnknownHostException ignored) { }

        String host = System.getenv("COMPUTERNAME");
        if (host != null) {
            return host;
        }

        host = System.getenv("HOSTNAME");
        if (host != null) {
            return host;
        }

        return "unknown";
    }


    public static String bytesToHex(byte[] bytes) {
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        StringBuilder buf = new StringBuilder(bytes.length * 2);
        for (byte aByte : bytes) {
            buf.append(hexDigits[(aByte & 0xf0) >> 4]);
            buf.append(hexDigits[aByte & 0x0f]);
        }
        return buf.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String getNormalizedArch() {
        final String arch = System.getProperty("os.arch");
        if (arch == null) {
            return null;
        }

        if (arch.equals("i386") || arch.equals("i486")  || arch.equals("i586") || arch.equals("i686")) {
            return "x86";
        }
        if (arch.equals("amd64") || arch.equals("x86_64")) {
            return "x64";
        }
        if (arch.equals("arm") || arch.equals("arm32")) {
            return "armle";
        }
        if (arch.equals("arm64")) {
            return "aarch64";
        }
        return arch;
    }
}
