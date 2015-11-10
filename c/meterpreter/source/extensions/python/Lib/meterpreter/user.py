import meterpreter_bindings

from meterpreter.core import *
from meterpreter.tlv import *

SYSTEM_SID = "S-1-5-18"

def getuid():
  resp = invoke_meterpreter('stdapi_sys_config_getuid', True)
  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_USER_NAME)['value']

def getsid():
  resp = invoke_meterpreter('stdapi_sys_config_getsid', True)
  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_SID)['value']

def is_system():
  return getsid() == SYSTEM_SID
