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
    private final InputStream inputStream;
    private final InputStream err;

    /**
     * Create a new process channel.
     *
     * @param meterpreter The meterpreter this channel should be assigned to.
     * @param process     Process of the channel
     */
    public ProcessChannel(Meterpreter meterpreter, Process process) {
        super(meterpreter, null, process.getOutputStream());
        this.inputStream = process.getInputStream();
        this.err = process.getErrorStream();
        this.process = process;
        Thread stdinThread = new InteractThread(this.inputStream, false);
        Thread stderrThread = new InteractThread(this.err, false);
        new CloseThread(stdinThread, stderrThread).start();
    }

    /**
     * Read at least one byte, and up to maxLength bytes from this stream.
     * An empty string (0 length data) is returned if no data is available.
     *
     * @param maxLength The maximum number of bytes to read.
     * @return The bytes read, or <code>null</code> if the end of the stream has been reached.
     */
    @Override
    public synchronized byte[] read(int maxLength) throws IOException, InterruptedException {
        if (closed) {
            return null;
        }
        if (active) {
            throw new IllegalStateException("Cannot read; currently interacting with this channel");
        }
        if (!waiting || (toRead != null && toRead.length == 0)) {
            return new byte[0];
        }
        if (toRead == null) {
            return null;
        }
        return super.read(maxLength);
    }

    @Override
    public void close() throws IOException {
        process.destroy();
        inputStream.close();
        err.close();
        super.close();
    }

    class CloseThread extends Thread {
        private final Thread stdinThread;
        private final Thread stderrThread;

        public CloseThread(Thread stdinThread, Thread stderrThread) {
            this.stdinThread = stdinThread;
            this.stderrThread = stderrThread;
        }

        @Override
        public void run() {
            try {
                stdinThread.start();
                stderrThread.start();
                stdinThread.join();
                stderrThread.join();
                handleInteract(null);
            } catch (Throwable t) {
                t.printStackTrace(meterpreter.getErrorStream());
            }
        }
    }

}
