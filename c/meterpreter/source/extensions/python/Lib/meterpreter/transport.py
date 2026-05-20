# Transport list/add helpers used to rely on TLV_TYPE_TRANS_* TLVs, which
# have been removed. Reimplement on the new C2 TLV shape before exposing
# these functions again.

def list():
  raise NotImplementedError("transport.list() pending rewrite onto C2 TLVs")

def add(url, session_expiry=None, comm_timeout=None, retry_total=None,
  retry_wait=None, ua=None, proxy_host=None, proxy_user=None,
  proxy_pass=None, cert_hash=None):
  raise NotImplementedError("transport.add() pending rewrite onto C2 TLVs")
