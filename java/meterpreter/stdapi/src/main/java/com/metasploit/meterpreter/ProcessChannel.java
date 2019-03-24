package com.metasploit.meterpreter;

import java.io.IOException;
import java.io.InputStream;

/**
 * A channel for a started {@link Process}.
 *
 * @author mihi
 */
public class ProcessChannel extends Channel {

    private final Process process;
    private final InputStream err;

    /**
     * Create a new process channel.
     *
     * @param meterpreter The meterpreter this channel should be assigned to.
     * @param process     Process of the channel
     */
    public ProcessChannel(Meterpreter meterpreter, Process process) {
        super(meterpreter, process.getInputStream(), process.getOutputStream());
        this.process = process;
        this.err = process.getErrorStream();
        new StderrThread(err).start();
    }

    public void close() throws IOException {
        process.destroy();
        err.close();
        super.close();
    }

    class StderrThread extends Thread {
        private final InputStream stream;

        public StderrThread(InputStream stream) {
            this.stream = stream;
        }

        public void run() {
            try {
                byte[] buffer = new byte[1024*1024];
                int len;
                while ((len = stream.read(buffer)) != -1) {
                    if (len == 0)
                        continue;
                    byte[] data = new byte[len];
                    System.arraycopy(buffer, 0, data, 0, len);
                    handleInteract(data);
                }
            } catch (Throwable t) {
                t.printStackTrace(meterpreter.getErrorStream());
            }
        }
    }

}
