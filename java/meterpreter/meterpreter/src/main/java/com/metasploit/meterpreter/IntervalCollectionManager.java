package com.metasploit.meterpreter;

import java.util.Enumeration;
import java.util.Hashtable;

public class IntervalCollectionManager {
    private final Hashtable<Integer, IntervalCollector> collectors;

    public IntervalCollectionManager() {
        this.collectors = new Hashtable<Integer, IntervalCollector>();
    }

    public void start() {
        // TODO: go through storage and see what is
        // currently in progress

        Enumeration ids = this.collectors.keys();

        while (ids.hasMoreElements()) {
            this.collectors.get(ids.nextElement()).start();
        }
    }
    
    public void addCollector(int id, IntervalCollector collector) {
        this.collectors.put(id, collector);
        collector.start();
    }

    public boolean pauseCollector(int id) {
        IntervalCollector collector = this.collectors.get(id);
        if (collector == null) {
            return false;
        }

        collector.pause();
        return true;
    }

    public boolean resumeCollector(int id) {
        IntervalCollector collector = this.collectors.get(id);
        if (collector == null) {
            return false;
        }

        collector.resume();
        return true;
    }

    public IntervalCollector stopCollector(int id) {
        IntervalCollector collector = this.collectors.get(id);
        if (collector == null) {
            return null;
        }

        collector.stop();
        this.collectors.remove(id);
        return collector;
    }

    public IntervalCollector getCollector(int id) {
        return this.collectors.get(id);
    }

    public void stop() {
        Enumeration ids = this.collectors.keys();

        while (ids.hasMoreElements()) {
            this.collectors.get(ids.nextElement()).stop();
            // TODO: get them to write to storage
        }
    }
}
