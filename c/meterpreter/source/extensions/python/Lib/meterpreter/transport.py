import meterpreter_bindings
import datetime

from meterpreter.core import *
from meterpreter.tlv import *

def list():
  resp = invoke_meterpreter('core_transport_list', True)
  if resp == None:
      return []

  transports = []
  for transport in packet_enum_tlvs(resp, TLV_TYPE_TRANS_GROUP):
    t = transport['value']
    transports.append({
      'URL': packet_get_tlv(t, TLV_TYPE_TRANS_URL)['value'],
      'CommTimeout': packet_get_tlv(t, TLV_TYPE_TRANS_COMM_TIMEOUT)['value'],
      'RetryTotal': packet_get_tlv(t, TLV_TYPE_TRANS_RETRY_TOTAL)['value'],
      'RetryWait': packet_get_tlv(t, TLV_TYPE_TRANS_RETRY_WAIT)['value'],
      'UA': packet_get_tlv_default(t, TLV_TYPE_TRANS_UA, None)['value'],
      'ProxyHost': packet_get_tlv_default(t, TLV_TYPE_TRANS_PROXY_HOST, None)['value'],
      'ProxyUser': packet_get_tlv_default(t, TLV_TYPE_TRANS_PROXY_USER, None)['value'],
      'ProxyPass': packet_get_tlv_default(t, TLV_TYPE_TRANS_PROXY_PASS, None)['value'],
      'CertHash': packet_get_tlv_default(t, TLV_TYPE_TRANS_CERT_HASH, None)['value']
    })

  expiry_secs = packet_get_tlv(resp, TLV_TYPE_TRANS_SESSION_EXP)['value']
  expiry = datetime.datetime.now() + datetime.timedelta(seconds=expiry_secs)
  return {
    'SessionExpiry': expiry,
    'Transports': transports
  }
