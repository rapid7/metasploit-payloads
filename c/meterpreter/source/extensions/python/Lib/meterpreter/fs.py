import meterpreter_bindings

from meterpreter.core import *
from meterpreter.tlv import *

def show_mount():
  resp = invoke_meterpreter('stdapi_fs_mount_show', True)
  if resp == None:
      return False

  mounts = []
  for mount in packet_enum_tlvs(resp, TLV_TYPE_MOUNT):
    m = mount['value']
    mounts.append({
      'Name': packet_get_tlv(m, TLV_TYPE_MOUNT_NAME)['value'],
      'Type': packet_get_tlv(m, TLV_TYPE_MOUNT_TYPE)['value'],
      'SpaceTotal': packet_get_tlv_default(m, TLV_TYPE_MOUNT_SPACE_TOTAL, None)['value'],
      'SpaceFree': packet_get_tlv_default(m, TLV_TYPE_MOUNT_SPACE_FREE, None)['value'],
      'SpaceUser': packet_get_tlv_default(m, TLV_TYPE_MOUNT_SPACE_USER, None)['value'],
      'UNC': packet_get_tlv_default(m, TLV_TYPE_MOUNT_UNCPATH, None)['value']
    })

  return mounts

