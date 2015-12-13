import sys, struct, random, string, meterpreter_bindings

# A stack of this stuff was stolen from the Python Meterpreter. We should look
# to find a nice way of sharing this across the two without the duplication.
#
# START OF COPY PASTE

#
# Constants
#

# these values will be patched, DO NOT CHANGE THEM
DEBUGGING = False
HTTP_CONNECTION_URL = None
HTTP_PROXY = None
HTTP_USER_AGENT = None
PAYLOAD_UUID = ''
SESSION_COMMUNICATION_TIMEOUT = 300
SESSION_EXPIRATION_TIMEOUT = 604800
SESSION_RETRY_TOTAL = 3600
SESSION_RETRY_WAIT = 10

PACKET_TYPE_REQUEST        = 0
PACKET_TYPE_RESPONSE       = 1
PACKET_TYPE_PLAIN_REQUEST  = 10
PACKET_TYPE_PLAIN_RESPONSE = 11

ERROR_SUCCESS = 0
# not defined in original C implementation
ERROR_FAILURE = 1
ERROR_FAILURE_PYTHON = 2
ERROR_FAILURE_WINDOWS = 3

CHANNEL_CLASS_BUFFERED = 0
CHANNEL_CLASS_STREAM   = 1
CHANNEL_CLASS_DATAGRAM = 2
CHANNEL_CLASS_POOL     = 3

#
# TLV Meta Types
#
TLV_META_TYPE_NONE       = (   0   )
TLV_META_TYPE_STRING     = (1 << 16)
TLV_META_TYPE_UINT       = (1 << 17)
TLV_META_TYPE_RAW        = (1 << 18)
TLV_META_TYPE_BOOL       = (1 << 19)
TLV_META_TYPE_QWORD      = (1 << 20)
TLV_META_TYPE_COMPRESSED = (1 << 29)
TLV_META_TYPE_GROUP      = (1 << 30)
TLV_META_TYPE_COMPLEX    = (1 << 31)
# not defined in original
TLV_META_TYPE_MASK = (1<<31)+(1<<30)+(1<<29)+(1<<19)+(1<<18)+(1<<17)+(1<<16)

#
# TLV base starting points
#
TLV_RESERVED   = 0
TLV_EXTENSIONS = 20000
TLV_USER       = 40000
TLV_TEMP       = 60000

#
# TLV Specific Types
#
TLV_TYPE_ANY                   = TLV_META_TYPE_NONE    | 0
TLV_TYPE_METHOD                = TLV_META_TYPE_STRING  | 1
TLV_TYPE_REQUEST_ID            = TLV_META_TYPE_STRING  | 2
TLV_TYPE_EXCEPTION             = TLV_META_TYPE_GROUP   | 3
TLV_TYPE_RESULT                = TLV_META_TYPE_UINT    | 4

TLV_TYPE_STRING                = TLV_META_TYPE_STRING  | 10
TLV_TYPE_UINT                  = TLV_META_TYPE_UINT    | 11
TLV_TYPE_BOOL                  = TLV_META_TYPE_BOOL    | 12

TLV_TYPE_LENGTH                = TLV_META_TYPE_UINT    | 25
TLV_TYPE_DATA                  = TLV_META_TYPE_RAW     | 26
TLV_TYPE_FLAGS                 = TLV_META_TYPE_UINT    | 27

TLV_TYPE_CHANNEL_ID            = TLV_META_TYPE_UINT    | 50
TLV_TYPE_CHANNEL_TYPE          = TLV_META_TYPE_STRING  | 51
TLV_TYPE_CHANNEL_DATA          = TLV_META_TYPE_RAW     | 52
TLV_TYPE_CHANNEL_DATA_GROUP    = TLV_META_TYPE_GROUP   | 53
TLV_TYPE_CHANNEL_CLASS         = TLV_META_TYPE_UINT    | 54
TLV_TYPE_CHANNEL_PARENTID      = TLV_META_TYPE_UINT    | 55

TLV_TYPE_SEEK_WHENCE           = TLV_META_TYPE_UINT    | 70
TLV_TYPE_SEEK_OFFSET           = TLV_META_TYPE_UINT    | 71
TLV_TYPE_SEEK_POS              = TLV_META_TYPE_UINT    | 72

TLV_TYPE_EXCEPTION_CODE        = TLV_META_TYPE_UINT    | 300
TLV_TYPE_EXCEPTION_STRING      = TLV_META_TYPE_STRING  | 301

TLV_TYPE_LIBRARY_PATH          = TLV_META_TYPE_STRING  | 400
TLV_TYPE_TARGET_PATH           = TLV_META_TYPE_STRING  | 401
TLV_TYPE_MIGRATE_PID           = TLV_META_TYPE_UINT    | 402
TLV_TYPE_MIGRATE_LEN           = TLV_META_TYPE_UINT    | 403

TLV_TYPE_TRANS_TYPE            = TLV_META_TYPE_UINT    | 430
TLV_TYPE_TRANS_URL             = TLV_META_TYPE_STRING  | 431
TLV_TYPE_TRANS_UA              = TLV_META_TYPE_STRING  | 432
TLV_TYPE_TRANS_COMM_TIMEOUT    = TLV_META_TYPE_UINT    | 433
TLV_TYPE_TRANS_SESSION_EXP     = TLV_META_TYPE_UINT    | 434
TLV_TYPE_TRANS_CERT_HASH       = TLV_META_TYPE_RAW     | 435
TLV_TYPE_TRANS_PROXY_HOST      = TLV_META_TYPE_STRING  | 436
TLV_TYPE_TRANS_PROXY_USER      = TLV_META_TYPE_STRING  | 437
TLV_TYPE_TRANS_PROXY_PASS      = TLV_META_TYPE_STRING  | 438
TLV_TYPE_TRANS_RETRY_TOTAL     = TLV_META_TYPE_UINT    | 439
TLV_TYPE_TRANS_RETRY_WAIT      = TLV_META_TYPE_UINT    | 440
TLV_TYPE_TRANS_GROUP           = TLV_META_TYPE_GROUP   | 441

TLV_TYPE_MACHINE_ID            = TLV_META_TYPE_STRING  | 460
TLV_TYPE_UUID                  = TLV_META_TYPE_RAW     | 461

TLV_TYPE_CIPHER_NAME           = TLV_META_TYPE_STRING  | 500
TLV_TYPE_CIPHER_PARAMETERS     = TLV_META_TYPE_GROUP   | 501

TLV_TYPE_PEER_HOST             = TLV_META_TYPE_STRING  | 1500
TLV_TYPE_PEER_PORT             = TLV_META_TYPE_UINT    | 1501
TLV_TYPE_LOCAL_HOST            = TLV_META_TYPE_STRING  | 1502
TLV_TYPE_LOCAL_PORT            = TLV_META_TYPE_UINT    | 1503

NULL_BYTE = '\x00'

is_str = lambda obj: issubclass(obj.__class__, str)
is_bytes = lambda obj: issubclass(obj.__class__, str)
bytes = lambda *args: str(*args[:1])
unicode = lambda x: (x.decode('UTF-8') if isinstance(x, str) else x)

def tlv_pack(*args):
  if len(args) == 2:
    tlv = {'type':args[0], 'value':args[1]}
  else:
    tlv = args[0]
  data = ''
  value = tlv['value']
  if (tlv['type'] & TLV_META_TYPE_UINT) == TLV_META_TYPE_UINT:
    if isinstance(value, float):
      value = int(round(value))
    data = struct.pack('>III', 12, tlv['type'], value)
  elif (tlv['type'] & TLV_META_TYPE_QWORD) == TLV_META_TYPE_QWORD:
    data = struct.pack('>IIQ', 16, tlv['type'], value)
  elif (tlv['type'] & TLV_META_TYPE_BOOL) == TLV_META_TYPE_BOOL:
    data = struct.pack('>II', 9, tlv['type']) + bytes(chr(int(bool(value))), 'UTF-8')
  else:
    if value.__class__.__name__ == 'unicode':
      value = value.encode('UTF-8')
    elif not is_bytes(value):
      value = bytes(value, 'UTF-8')
    if (tlv['type'] & TLV_META_TYPE_STRING) == TLV_META_TYPE_STRING:
      data = struct.pack('>II', 8 + len(value) + 1, tlv['type']) + value + NULL_BYTE
    elif (tlv['type'] & TLV_META_TYPE_RAW) == TLV_META_TYPE_RAW:
      data = struct.pack('>II', 8 + len(value), tlv['type']) + value
    elif (tlv['type'] & TLV_META_TYPE_GROUP) == TLV_META_TYPE_GROUP:
      data = struct.pack('>II', 8 + len(value), tlv['type']) + value
    elif (tlv['type'] & TLV_META_TYPE_COMPLEX) == TLV_META_TYPE_COMPLEX:
      data = struct.pack('>II', 8 + len(value), tlv['type']) + value
  return data

def packet_enum_tlvs(pkt, tlv_type = None):
  offset = 0
  while (offset < len(pkt)):
    tlv = struct.unpack('>II', pkt[offset:offset+8])
    if (tlv_type == None) or ((tlv[1] & ~TLV_META_TYPE_COMPRESSED) == tlv_type):
      val = pkt[offset+8:(offset+8+(tlv[0] - 8))]
      if (tlv[1] & TLV_META_TYPE_STRING) == TLV_META_TYPE_STRING:
        val = str(val.split(NULL_BYTE, 1)[0])
      elif (tlv[1] & TLV_META_TYPE_UINT) == TLV_META_TYPE_UINT:
        val = struct.unpack('>I', val)[0]
      elif (tlv[1] & TLV_META_TYPE_QWORD) == TLV_META_TYPE_QWORD:
        val = struct.unpack('>Q', val)[0]
      elif (tlv[1] & TLV_META_TYPE_BOOL) == TLV_META_TYPE_BOOL:
        val = bool(struct.unpack('b', val)[0])
      elif (tlv[1] & TLV_META_TYPE_RAW) == TLV_META_TYPE_RAW:
        pass
      yield {'type':tlv[1], 'length':tlv[0], 'value':val}
    offset += tlv[0]
  raise StopIteration()

def packet_get_tlv(pkt, tlv_type):
  try:
    tlv = list(packet_enum_tlvs(pkt, tlv_type))[0]
  except IndexError:
    return {}
  return tlv

def packet_get_tlv_default(pkt, tlv_type, default):
  try:
    tlv = list(packet_enum_tlvs(pkt, tlv_type))[0]
  except IndexError:
    return {'value': default}
  return tlv

# END OF COPY PASTE

def validate_binding(required):
  """Makes sure that the current set of bindings that is available
  in Meterpreter's bindings list contains that required by the caller.
  This function returns the correct binding name to call."""

  # assume all core commands are valid
  if required[:5] == 'core_':
    required = 'meterpreter_core'

  if not required in set(dir(meterpreter_bindings)):
    raise Exception('Missing bindings: {0}'.format(required))

  return required

def invoke_meterpreter(method, is_local, tlv = ""):
  binding = validate_binding(method)

  header = struct.pack('>I', PACKET_TYPE_REQUEST)
  header += tlv_pack(TLV_TYPE_METHOD, method)
  header += tlv_pack(TLV_TYPE_REQUEST_ID, 0)
  req = struct.pack('>I', len(header) + len(tlv) + 4) + header + tlv

  return getattr(meterpreter_bindings, binding)(is_local, req)

def rnd_string(n):
  return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(n))

