import meterpreter_bindings

from meterpreter.core import *

TLV_STDAPI_EXTENSION = 0

TLV_TYPE_COMPUTER_NAME         = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1040)
TLV_TYPE_OS_NAME               = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1041)
TLV_TYPE_ARCHITECTURE          = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1043)
TLV_TYPE_LANG_SYSTEM           = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1044)
TLV_TYPE_DOMAIN                = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1046)
TLV_TYPE_LOGGED_ON_USER_COUNT  = TLV_META_TYPE_UINT   | (TLV_STDAPI_EXTENSION + 1047)

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

