package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.CommandManager;
import com.metasploit.meterpreter.ExtensionLoader;

/**
 * Loader class to register all the core commands.
 *
 * @author mihi
 */
public class Loader implements ExtensionLoader {

    public void load(CommandManager mgr) throws Exception {
        mgr.registerCommand("core_channel_close", core_channel_close.class);
        mgr.registerCommand("core_channel_eof", core_channel_eof.class);
        mgr.registerCommand("core_channel_interact", core_channel_interact.class);
        mgr.registerCommand("core_channel_open", core_channel_open.class);
        mgr.registerCommand("core_channel_read", core_channel_read.class);
        mgr.registerCommand("core_channel_write", core_channel_write.class);
        mgr.registerCommand("core_loadlib", core_loadlib.class);
        mgr.registerCommand("core_uuid", core_uuid.class);
        mgr.registerCommand("core_machine_id", core_machine_id.class);
        mgr.registerCommand("core_shutdown", core_shutdown.class);
        mgr.registerCommand("core_transport_set_timeouts", core_transport_set_timeouts.class);
        mgr.registerCommand("core_transport_list", core_transport_list.class);
        mgr.registerCommand("core_transport_add", core_transport_add.class);
        mgr.registerCommand("core_transport_change", core_transport_change.class);
        mgr.registerCommand("core_transport_sleep", core_transport_sleep.class);
        mgr.registerCommand("core_transport_next", core_transport_next.class);
        mgr.registerCommand("core_transport_prev", core_transport_prev.class);
        mgr.registerCommand("core_transport_remove", core_transport_remove.class);
    }
}
