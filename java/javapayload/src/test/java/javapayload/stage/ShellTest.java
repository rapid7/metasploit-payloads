package javapayload.stage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;

import junit.framework.TestCase;

public class ShellTest extends TestCase {

    public void testShellStage() throws Exception {
        Shell shell = new Shell();
        String commands = "echo MagicToken\r\nexit\r\n";
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(commands.getBytes("ISO-8859-1")));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        shell.start(in, out, new String[]{"Payload", "--", "Shell"});
        int timeout = 5000;
        while (out.size() == 0 && timeout > 0) {
            Thread.sleep(100);
            timeout -= 100;
        }
        String shellOutput = out.toString("ISO-8859-1");
//        Assert.assertTrue("MagicToken missing in shell output: " + shellOutput, shellOutput.contains("MagicToken"));
//        Assert.assertEquals(-1, in.read());
    }
}
