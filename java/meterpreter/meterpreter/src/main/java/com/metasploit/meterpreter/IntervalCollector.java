package com.metasploit.meterpreter;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.List;

public abstract class IntervalCollector {
    private long timeout;
    private boolean isCollecting;
    private Thread thread;
    private BlockingQueue queue;

    private class IntervalRunner implements Runnable {
        private final IntervalCollector collector;

        public IntervalRunner(IntervalCollector collector) {
            this.collector = collector;
        }

        public void run() {
            this.collector.threadFunc();
        }
    }

    protected IntervalCollector(long timeout) {
        this.timeout = timeout;

        // use an array blocking queue of length 1, which is used
        // as a mechanism to stop the processing if required.
        this.queue = new ArrayBlockingQueue(1);
    }

    private void threadFunc() {
      this.init();
      this.isCollecting = true;

      while (this.isRunning()) {
          try {
              if (this.queue.poll(this.timeout, TimeUnit.SECONDS) == null) {
                  // timeout occured and nothing was in the queue, so process
                  // the collection
                  if (this.isCollecting) {
                      this.collect();
                  }
              }
              else {
                  // something was put in the queue, which is our signal to finish
                  this.thread = null;
              }
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

    public abstract boolean dump(TLVPacket packet);

    public boolean isRunning() {
        return this.thread != null;
    }

    protected long getTimeout() {
        return this.timeout;
    }

    protected abstract void collect();
    protected abstract void init();
    protected abstract void deinit();
}

