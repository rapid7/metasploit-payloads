import meterpreter_bindings
import datetime

from meterpreter.core import *
from meterpreter.tlv import *

def list():
  resp = invoke_meterpreter('core_transport_list', True)
  if resp == None:
      return []

  if packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] != 0:
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

def add(url, session_expiry=None, comm_timeout=None, retry_total=None,
  retry_wait=None, ua=None, proxy_host=None, proxy_user=None,
  proxy_pass=None, cert_hash=None):

  tlv = tlv_pack(TLV_TYPE_TRANS_URL, url)

  if session_expiry:
    tlv += tlv_pack(TLV_TYPE_TRANS_SESSION_EXP, session_expiry)
  if comm_timeout:
    tlv += tlv_pack(TLV_TYPE_TRANS_COMM_TIMEOUT, comm_timeout)
  if retry_total:
    tlv += tlv_pack(TLV_TYPE_TRANS_RETRY_TOTAL, retry_total)
  if retry_wait:
    tlv += tlv_pack(TLV_TYPE_TRANS_RETRY_WAIT, retry_wait)
  if ua:
    tlv += tlv_pack(TLV_TYPE_TRANS_UA, ua)
  if proxy_host:
    tlv += tlv_pack(TLV_TYPE_TRANS_PROXY_HOST, proxy_host)
  if proxy_user:
    tlv += tlv_pack(TLV_TYPE_TRANS_PROXY_USER, proxy_user)
  if proxy_pass:
    tlv += tlv_pack(TLV_TYPE_TRANS_PROXY_PASS, proxy_pass)
  if cert_hash:
    tlv += tlv_pack(TLV_TYPE_TRANS_CERT_HASH, cert_hash)

  resp = invoke_meterpreter('core_transport_add', True, tlv)
  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0

