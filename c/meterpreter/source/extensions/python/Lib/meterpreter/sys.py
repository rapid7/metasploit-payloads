import meterpreter_bindings

from meterpreter.core import *
from meterpreter.tlv import *

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

def ps_list():
  resp = invoke_meterpreter('stdapi_sys_process_get_processes', True)
  if resp == None:
      return False

  processes = []
  for group in packet_enum_tlvs(resp, TLV_TYPE_PROCESS_GROUP):
    g = group['value']
    arch = packet_get_tlv(g, TLV_TYPE_PROCESS_ARCH)
    processes.append({
      'Arch': 'x86' if arch == 1 else 'x86_64',
      'Pid': packet_get_tlv(g, TLV_TYPE_PID)['value'],
      'PPid': packet_get_tlv(g, TLV_TYPE_PARENT_PID)['value'],
      'Name': packet_get_tlv(g, TLV_TYPE_PROCESS_NAME)['value'],
      'Path': packet_get_tlv(g, TLV_TYPE_PROCESS_PATH)['value'],
      'Session': packet_get_tlv(g, TLV_TYPE_PROCESS_SESSION)['value'],
      'User': packet_get_tlv(g, TLV_TYPE_USER_NAME)['value']
    })

  return processes

