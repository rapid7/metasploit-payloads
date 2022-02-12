package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.CommandManager;
import com.metasploit.meterpreter.command.CommandId;
import com.metasploit.meterpreter.ExtensionLoader;

/**
 * Loader class to register all the core commands.
 *
 * @author mihi
 */
public class Loader implements ExtensionLoader {

    public void load(CommandManager mgr) throws Exception {
        mgr.registerCommand(CommandId.CORE_CHANNEL_CLOSE, core_channel_close.class);
        mgr.registerCommand(CommandId.CORE_CHANNEL_EOF, core_channel_eof.class);
        mgr.registerCommand(CommandId.CORE_CHANNEL_INTERACT, core_channel_interact.class);
        mgr.registerCommand(CommandId.CORE_CHANNEL_READ, core_channel_read.class);
        mgr.registerCommand(CommandId.CORE_CHANNEL_WRITE, core_channel_write.class);
        mgr.registerCommand(CommandId.CORE_ENUMEXTCMD, core_enumextcmd.class);
        mgr.registerCommand(CommandId.CORE_LOADLIB, core_loadlib.class);
        mgr.registerCommand(CommandId.CORE_SET_UUID, core_set_uuid.class);
        mgr.registerCommand(CommandId.CORE_MACHINE_ID, core_machine_id.class);
        mgr.registerCommand(CommandId.CORE_GET_SESSION_GUID, core_get_session_guid.class);
        mgr.registerCommand(CommandId.CORE_SET_SESSION_GUID, core_set_session_guid.class);
        mgr.registerCommand(CommandId.CORE_PATCH_URL, core_patch_url.class);
        mgr.registerCommand(CommandId.CORE_SHUTDOWN, core_shutdown.class);
        mgr.registerCommand(CommandId.CORE_TRANSPORT_SET_TIMEOUTS, core_transport_set_timeouts.class);
        mgr.registerCommand(CommandId.CORE_TRANSPORT_LIST, core_transport_list.class);
        mgr.registerCommand(CommandId.CORE_TRANSPORT_ADD, core_transport_add.class);
        mgr.registerCommand(CommandId.CORE_TRANSPORT_CHANGE, core_transport_change.class);
        mgr.registerCommand(CommandId.CORE_TRANSPORT_SLEEP, core_transport_sleep.class);
        mgr.registerCommand(CommandId.CORE_TRANSPORT_NEXT, core_transport_next.class);
        mgr.registerCommand(CommandId.CORE_TRANSPORT_PREV, core_transport_prev.class);
        mgr.registerCommand(CommandId.CORE_TRANSPORT_REMOVE, core_transport_remove.class);
        mgr.registerCommand(CommandId.CORE_NEGOTIATE_TLV_ENCRYPTION, core_negotiate_tlv_encryption.class);
        mgr.registerCommand(CommandId.CORE_NATIVE_ARCH, core_native_arch.class);
    }
}
