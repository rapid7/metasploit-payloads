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

    /**
     * Read at least one byte, and up to maxLength bytes from this stream.
     *
     * @param maxLength The maximum number of bytes to read.
     * @return The bytes read, or <code>null</code> if the end of the stream has been reached.
     */
    public synchronized byte[] read(int maxLength) {
        if (closed)
            return null;
        if (active)
            throw new IllegalStateException("Cannot read; currently interacting with this channel");
        if (!waiting || (toRead != null && toRead.length == 0))
            return new byte[0];
        if (toRead == null)
            return null;
        byte[] result = new byte[Math.min(toRead.length, maxLength)];
        System.arraycopy(toRead, 0, result, 0, result.length);
        byte[] rest = new byte[toRead.length - result.length];
        System.arraycopy(toRead, result.length, rest, 0, rest.length);
        toRead = rest;
        notifyAll();
        return result;
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
