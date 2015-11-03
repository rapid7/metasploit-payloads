import meterpreter_bindings

from meterpreter.core import *

TLV_STDAPI_EXTENSION = 0

TLV_TYPE_COMPUTER_NAME         = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1040)
TLV_TYPE_OS_NAME               = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1041)
TLV_TYPE_USER_NAME             = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1042)
TLV_TYPE_ARCHITECTURE          = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1043)
TLV_TYPE_LANG_SYSTEM           = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1044)
TLV_TYPE_DOMAIN                = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1046)
TLV_TYPE_LOGGED_ON_USER_COUNT  = TLV_META_TYPE_UINT   | (TLV_STDAPI_EXTENSION + 1047)

TLV_TYPE_PID                   = TLV_META_TYPE_UINT   | (TLV_STDAPI_EXTENSION + 2300)
TLV_TYPE_PROCESS_NAME          = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 2301)
TLV_TYPE_PROCESS_PATH          = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 2302)
TLV_TYPE_PROCESS_GROUP         = TLV_META_TYPE_GROUP  | (TLV_STDAPI_EXTENSION + 2303)
TLV_TYPE_PROCESS_ARCH          = TLV_META_TYPE_UINT   | (TLV_STDAPI_EXTENSION + 2306)
TLV_TYPE_PARENT_PID            = TLV_META_TYPE_UINT   | (TLV_STDAPI_EXTENSION + 2307)
TLV_TYPE_PROCESS_SESSION       = TLV_META_TYPE_UINT   | (TLV_STDAPI_EXTENSION + 2308)

def info():
  resp = invoke_meterpreter('stdapi_sys_config_sysinfo', True)
  if resp == None:
    return False

  return {
    'Host': packet_get_tlv(resp, TLV_TYPE_COMPUTER_NAME)['value'],
    'OS': packet_get_tlv(resp, TLV_TYPE_OS_NAME)['value'],
    'Arch': packet_get_tlv(resp, TLV_TYPE_ARCHITECTURE)['value'],
    'Lang': packet_get_tlv(resp, TLV_TYPE_LANG_SYSTEM)['value'],
    'Domain': packet_get_tlv(resp, TLV_TYPE_DOMAIN)['value'],
    'LoggedOn': packet_get_tlv(resp, TLV_TYPE_LOGGED_ON_USER_COUNT)['value']
  }

def ps_list():
  resp = invoke_meterpreter('stdapi_sys_process_get_processes', True)
  if resp == None:
      return False

  processes = []
  for group in packet_enum_tlvs(resp, TLV_TYPE_PROCESS_GROUP):
    g = group['value']
    arch = packet_get_tlv(g, TLV_TYPE_PROCESS_ARCH)
    processes.append({
      'Arch': 'x86' if arch == 1 else 'x86_64',
      'Pid': packet_get_tlv(g, TLV_TYPE_PID)['value'],
      'PPid': packet_get_tlv(g, TLV_TYPE_PARENT_PID)['value'],
      'Name': packet_get_tlv(g, TLV_TYPE_PROCESS_NAME)['value'],
      'Path': packet_get_tlv(g, TLV_TYPE_PROCESS_PATH)['value'],
      'Session': packet_get_tlv(g, TLV_TYPE_PROCESS_SESSION)['value'],
      'User': packet_get_tlv(g, TLV_TYPE_USER_NAME)['value']
    })

  return processes

