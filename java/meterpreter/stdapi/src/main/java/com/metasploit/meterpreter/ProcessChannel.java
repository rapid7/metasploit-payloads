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
        super(meterpreter, process.getInputStream(), process.getOutputStream(), true);
        this.err = process.getErrorStream();
        this.process = process;
        new StdoutStderrThread(this.in, this.err).start();
    }

    /**
     * Read at least one byte, and up to maxLength bytes from this stream.
     * An empty string (0 length data) is returned if no data is available.
     *
     * @param maxLength The maximum number of bytes to read.
     * @return The bytes read, or <code>null</code> if the end of the stream has been reached.
     */
    public synchronized byte[] read(int maxLength) throws IOException, InterruptedException {
        if (closed)
            return null;
        if (active)
            throw new IllegalStateException("Cannot read; currently interacting with this channel");
        if (!waiting || (toRead != null && toRead.length == 0))
            return new byte[0];
        if (toRead == null)
            return null;
        return super.read(maxLength);
    }

    public void close() throws IOException {
        process.destroy();
        err.close();
        super.close();
    }

    class StdoutStderrThread extends Thread {
        private final InputStream in;
        private final InputStream err;

        public StdoutStderrThread(InputStream in, InputStream err) {
            this.in = in;
            this.err = err;
        }

        public void run() {
            try {
                byte[] buffer = new byte[1024*1024];
                int inlen;
                int errlen;
                while (true) {
                    if ((inlen = in.read(buffer)) != -1) {
                        if (inlen > 0)
                            writeBuf(buffer, inlen);
                    }
                    if ((errlen = err.read(buffer)) != -1) {
                        if (errlen > 0)
                            writeBuf(buffer, errlen);
                    }
                    if (inlen == -1 && errlen == -1) {
                        break;
                    }
                }
                handleInteract(null);
            } catch (Throwable t) {
                t.printStackTrace(meterpreter.getErrorStream());
            }
        }

        private void writeBuf(byte[] buffer, int len) throws IOException, InterruptedException {
            byte[] data = new byte[len];
            System.arraycopy(buffer, 0, data, 0, len);
            handleInteract(data);
        }
    }

}
