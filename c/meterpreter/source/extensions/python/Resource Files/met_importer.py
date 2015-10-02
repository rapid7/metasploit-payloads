import sys, imp, marshal

class MetLoader:
  def __init__(self, libs):
    self.libs = libs
    #print libs.keys()

  def load_module(self, name):
    print 'Searching for: {0}'.format(name)
    if name in sys.modules:
      return sys.modules[name]

    if not name in self.libs:
      print 'No lib: {0}'.format(name)
      return None

    filename, package, code = self.libs[name]

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
        print 'Executed code for: {0}'.format(name)
      except e:
        del sys.modules[name]
        mod = None
    except:
      mod = None
    finally:
      imp.release_lock()

    print 'Result for {0}: {1}'.format(name, mod != None)
    return mod

class MetFinder:
  def __init__(self, libs):
    self.loader = MetLoader(libs)

  def find_module(self, name, path = None):
    return self.loader

