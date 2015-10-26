import meterpreter_bindings

from meterpreter.core import *

TLV_EXTAPI_EXTENSION = 20000

TLV_TYPE_EXTAPI_ADSI_DOMAIN       = TLV_META_TYPE_STRING  | (TLV_EXTAPI_EXTENSION + 54)
TLV_TYPE_EXTAPI_ADSI_FILTER       = TLV_META_TYPE_STRING  | (TLV_EXTAPI_EXTENSION + 55)
TLV_TYPE_EXTAPI_ADSI_FIELD        = TLV_META_TYPE_STRING  | (TLV_EXTAPI_EXTENSION + 56)
TLV_TYPE_EXTAPI_ADSI_RESULT       = TLV_META_TYPE_GROUP   | (TLV_EXTAPI_EXTENSION + 57)
TLV_TYPE_EXTAPI_ADSI_MAXRESULTS   = TLV_META_TYPE_UINT    | (TLV_EXTAPI_EXTENSION + 58)
TLV_TYPE_EXTAPI_ADSI_PAGESIZE     = TLV_META_TYPE_UINT    | (TLV_EXTAPI_EXTENSION + 59)
TLV_TYPE_EXTAPI_ADSI_ARRAY        = TLV_META_TYPE_GROUP   | (TLV_EXTAPI_EXTENSION + 60)
TLV_TYPE_EXTAPI_ADSI_STRING       = TLV_META_TYPE_STRING  | (TLV_EXTAPI_EXTENSION + 61)
TLV_TYPE_EXTAPI_ADSI_NUMBER       = TLV_META_TYPE_UINT    | (TLV_EXTAPI_EXTENSION + 62)
TLV_TYPE_EXTAPI_ADSI_BIGNUMBER    = TLV_META_TYPE_QWORD   | (TLV_EXTAPI_EXTENSION + 63)
TLV_TYPE_EXTAPI_ADSI_BOOL         = TLV_META_TYPE_BOOL    | (TLV_EXTAPI_EXTENSION + 64)
TLV_TYPE_EXTAPI_ADSI_RAW          = TLV_META_TYPE_RAW     | (TLV_EXTAPI_EXTENSION + 65)
TLV_TYPE_EXTAPI_ADSI_PATH         = TLV_META_TYPE_GROUP   | (TLV_EXTAPI_EXTENSION + 66)
TLV_TYPE_EXTAPI_ADSI_PATH_VOL     = TLV_META_TYPE_STRING  | (TLV_EXTAPI_EXTENSION + 67)
TLV_TYPE_EXTAPI_ADSI_PATH_PATH    = TLV_META_TYPE_STRING  | (TLV_EXTAPI_EXTENSION + 68)
TLV_TYPE_EXTAPI_ADSI_PATH_TYPE    = TLV_META_TYPE_UINT    | (TLV_EXTAPI_EXTENSION + 69)
TLV_TYPE_EXTAPI_ADSI_DN           = TLV_META_TYPE_GROUP   | (TLV_EXTAPI_EXTENSION + 70)

def enum_dcs(domain_name, max_results = None, page_size = None):
  query_filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
  fields = ['name', 'dnshostname', 'distinguishedname', 'operatingsystem',
      'operatingsystemversion', 'operatingsystemservicepack', 'description', 'comment']
  return domain_query(domain_name, query_filter, fields, max_results, page_size)

def enum_users(domain_name, max_results = None, page_size = None):
  query_filter = '(objectClass=user)'
  fields = ['samaccountname', 'name', 'distinguishedname', 'description', 'comment']
  return domain_query(domain_name, query_filter, fields, max_results, page_size)

def enum_groups(domain_name, max_results = None, page_size = None):
  query_filter = '(objectClass=group)'
  fields = ['name', 'distinguishedname', 'description']
  return domain_query(domain_name, query_filter, fields, max_results, page_size)

def enum_group_users_nested(domain_name, group_dn, max_results = None, page_size = None):
  query_filter = '(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:={0}))'.format(group_dn)
  fields = ['samaccountname', 'name', 'distinguishedname', 'description', 'comment']
  return domain_query(domain_name, query_filter, fields, max_results, page_size)

def enum_computers(domain_name, max_results = None, page_size = None):
  query_filter = '(objectClass=computer)'
  fields = ['name', 'dnshostname', 'distinguishedname', 'operatingsystem',
      'operatingsystemversion', 'operatingsystemservicepack', 'description', 'comment']
  return domain_query(domain_name, query_filter, fields, max_results, page_size)

def domain_query(domain_name, query_filter, fields, max_results = None, page_size = None):
  tlv = tlv_pack(TLV_TYPE_EXTAPI_ADSI_DOMAIN, domain_name)
  tlv += tlv_pack(TLV_TYPE_EXTAPI_ADSI_FILTER, query_filter)
  if max_results:
    tlv += tlv_pack(TLV_TYPE_EXTAPI_ADSI_MAXRESULTS, max_results)
  if page_size:
    tlv += tlv_pack(TLV_TYPE_EXTAPI_ADSI_PAGESIZE, page_size)

  for f in fields:
    tlv += tlv_pack(TLV_TYPE_EXTAPI_ADSI_FIELD, f)

  resp = invoke_meterpreter('extapi_adsi_domain_query', True, tlv)
  if resp == None:
    return None

  if packet_get_tlv(resp, TLV_TYPE_RESULT)['value'] != 0:
    return None

  results = []
  for result_tlv in packet_enum_tlvs(resp, TLV_TYPE_EXTAPI_ADSI_RESULT):
    results.append(extract_values(result_tlv['value'], fields))

  return results

def extract_values(result_tlv, fields = None):
  if fields:
    values = [extract_value(v['type'], v['value'], fields[i]) for i, v in enumerate(packet_enum_tlvs(result_tlv))]
    return dict(values)

  return [extact_value(v['type'], v['value'], None) for v in packet_enum_tlvs(result_tlv)]

def extract_value(vtype, vval, field = None):
  result = None

  if vtype == TLV_TYPE_EXTAPI_ADSI_STRING:
    result = ('string', vval)
  elif vtype == TLV_TYPE_EXTAPI_ADSI_NUMBER:
    result = ('int', vval)
  elif vtype == TLV_TYPE_EXTAPI_ADSI_BIGNUMBER:
    result = ('int', vval)
  elif vtype == TLV_TYPE_EXTAPI_ADSI_BOOL:
    result = ('bool', vval != 0)
  elif vtype == TLV_TYPE_EXTAPI_ADSI_RAW:
    result = ('raw', vval)
  elif vtype == TLV_TYPE_EXTAPI_ADSI_ARRAY:
    result = ('array', extract_values(vval))
  elif vtype == TLV_TYPE_EXTAPI_ADSI_PATH:
    vol = packet_get_tlv(vval, TLV_TYPE_EXTAPI_ADSI_PATH_VOL)
    path = packet_get_tlv(vval, TLV_TYPE_EXTAPI_ADSI_PATH_PATH)
    vol_type = packet_get_tlv(vval, TLV_TYPE_EXTAPI_ADSI_PATH_TYPE)
    result = ('path', vol, path, vol_type)
  elif vtype == TLV_TYPE_EXTAPI_ADSI_DN:
    values = list(packet_enum_tlvs(vval))
    val_type = 'string' if values[1].type == TLV_TYPE_EXTAPI_ADSI_STRING else 'raw'
    result = ('dn', values[0].value, val_type, values[1].value)
  else:
    result = ('unknown', vval)

  if field:
    return (field, result)

  return result
