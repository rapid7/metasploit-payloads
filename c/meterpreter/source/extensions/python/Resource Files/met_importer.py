import sys, imp, marshal

met_dbg_trace = False
met_mod_name = None
met_mod_body = None

def met_init(dbg):
  global met_dbg_trace
  global met_finder
  global met_lib_data
  met_dbg_trace = dbg
  met_finder = MetFinder(met_lib_data[1])
  sys.meta_path=[met_finder]
  if not dbg:
    del met_lib_data

def met_dbg(s):
  global met_dbg_trace
  if met_dbg_trace:
    print s

def met_import_code():
  global met_mod_body
  global met_mod_name
  global met_finder
  try:
    if met_mod_body != None:
      if met_mod_name == None:
        met_mod_name = 'met_imported_code'

      if met_mod_body[:4] == imp.get_magic():
        met_mod_body = marshal.loads(met_mod_body[8:])
      else:
        met_mod_body = compile(met_mod_body, met_mod_name, 'exec')
      met_finder.loader.add_module(met_mod_name, met_mod_body)
    else:
      raise ValueError("met_mod_body not specified")
  finally:
    # always reset these two
    met_mod_name = None
    met_mod_body = None

class MetLoader:
  def __init__(self, libs):
    self.libs = libs
    if met_dbg_trace:
      for l in libs.keys():
        met_dbg(l)
      met_dbg('Total libs: {0}'.format(len(libs.keys())))

  def add_module(self, name, code):
    imp.acquire_lock()

    try:
      mod = imp.new_module(name)
      sys.modules[name] = mod

      try:
        mod.__file__ = name + ".py"
        exec code in mod.__dict__
        mod.__loader__ = self
        met_dbg('Executed code for: {0}'.format(name))
      except e:
        del sys.modules[name]
        mod = None
    except:
      mod = None
    finally:
      imp.release_lock()

    met_dbg('Result for {0}: {1}'.format(name, mod != None))

  def load_module(self, name):
    met_dbg('Searching for: {0}'.format(name))
    if name in sys.modules:
      met_dbg('Already loaded: {0}'.format(name))
      return sys.modules[name]

    if not name in self.libs:
      if '.' in name:
        parts = name.split('.')
        result = self.load_module('.'.join(parts[1:]))
        if result == None and len(parts) >= 3:
          result = self.load_module('.'.join(parts[0:-2] + [parts[-1]]))
        return result

      met_dbg('No lib: {0}'.format(name))
      return None
    met_dbg('Lib exists: {0}'.format(name))

    filename, package, code = self.libs[name]
    met_dbg('Lib details: {0} - {1}'.format(filename, package))

    imp.acquire_lock()
    mod = None

    try:
      mod = imp.new_module(name)
      sys.modules[name] = mod

      try:
        mod.__file__ = filename
        if package:
          mod.__path__ = [name.replace('.', '\\')]
        exec code in mod.__dict__
        mod.__loader__ = self
        met_dbg('Executed code for: {0}'.format(name))
      except Exception as e:
        met_dbg('Exception thrown importing module: {0} - {1}'.format(name, e))
        del sys.modules[name]
        mod = None
    except Exception as ex:
      met_dbg('Exception thrown starting import: {0} - {1}'.format(name, ex))
      mod = None
    finally:
      imp.release_lock()

    #if mod == None and '.' in name:
      #return self.load_module('.'.join(name.split('.')[1:]))

    met_dbg('Result for {0}: {1}'.format(name, mod != None))
    return mod

class MetFinder:
  def __init__(self, libs):
    self.loader = MetLoader(libs)

  def find_module(self, name, path = None):
    met_dbg('find_module: {0} {1}'.format(name, path))
    return self.loader

