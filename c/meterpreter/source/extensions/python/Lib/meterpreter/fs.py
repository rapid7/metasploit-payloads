import meterpreter_bindings

from meterpreter.core import *

TLV_STDAPI_EXTENSION = 0

TLV_TYPE_MOUNT                 = TLV_META_TYPE_GROUP  | (TLV_STDAPI_EXTENSION + 1207)
TLV_TYPE_MOUNT_NAME            = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1208)
TLV_TYPE_MOUNT_TYPE            = TLV_META_TYPE_UINT   | (TLV_STDAPI_EXTENSION + 1209)
TLV_TYPE_MOUNT_SPACE_USER      = TLV_META_TYPE_QWORD  | (TLV_STDAPI_EXTENSION + 1210)
TLV_TYPE_MOUNT_SPACE_TOTAL     = TLV_META_TYPE_QWORD  | (TLV_STDAPI_EXTENSION + 1211)
TLV_TYPE_MOUNT_SPACE_FREE      = TLV_META_TYPE_QWORD  | (TLV_STDAPI_EXTENSION + 1212)
TLV_TYPE_MOUNT_UNCPATH         = TLV_META_TYPE_STRING | (TLV_STDAPI_EXTENSION + 1213)

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

