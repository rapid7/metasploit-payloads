#!/usr/bin/env python

import os,struct,py_compile,zlib,marshal

def w(f,c):
  with open(f,'wb') as f:
    f.write(c)

def r(f):
  with open(f,'rb') as f:
    return f.read()

def p(d):
  return struct.pack('<L', d)

modules = {}

here = os.getcwd()
folder = '../Lib'
os.chdir(folder)

for entry in os.listdir('.'):
  if os.path.isfile(entry):
    if entry.endswith('.py'):
      path = entry.split('.')[0]
      print path
      modules[path] = (entry, False, compile(r(entry), entry, 'exec'))
  else:
    for root, _, files in os.walk(entry):
      for f in [x for x in files if x.endswith('.py')]:
        path = os.path.join(root, f)
        modname = path.split('.')[0].replace('\\', '.').replace('.__init__', '')
        print modname
        modules[modname] = (path, True, compile(r(path), path, 'exec'))

os.chdir(here)

importer = compile(r('met_importer.py'), 'met_importer.py', 'exec')
print 'Total modules: {0}'.format(len(modules.keys()))

content = zlib.compress(marshal.dumps([importer, modules]), 9)
w('python_core.cz', p(len(content)) + content)

