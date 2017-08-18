#!/usr/bin/env python

import os, sys

rel = 'Release'
if len(sys.argv) == 2 and sys.argv[1] == 'debug':
  print '[*] Using debug library ...'
  rel = 'Debug'

bin_path = os.path.join('..', 'MSF.Powershell', 'bin', rel, 'MSF.Powershell.dll')
target_path = os.path.join('..', '..', 'c', 'meterpreter', 'source', 'extensions', 'powershell')
size_var = 'PSHRUNNER_DLL_LEN'

def read_all(path):
  with open(path, 'rb') as f:
    return f.read()

def write_all(path, content):
  if os.path.isfile(path):
    os.remove(path)
  with open(path, 'wb') as f:
    f.write(content)

def chunks(l, n):
  for i in xrange(0, len(l), n):
    yield l[i:i + n]

binary = read_all(bin_path)

header  = ''
header += '/*!\n'
header += ' * @file powershell_runner.h\n'
header += ' * @brief This file is generated, do not modify directly.\n'
header += ' */\n\n'
header += '#ifndef _METERPRETER_SOURCE_EXTENSION_POWERSHELL_RUNNER_H\n'
header += '#define _METERPRETER_SOURCE_EXTENSION_POWERSHELL_RUNNER_H\n\n'
header += '#define {0} {1}\n\n'.format(size_var, len(binary))
header += 'extern unsigned char PowerShellRunnerDll[{0}];\n\n'.format(size_var)
header += '#endif\n'

source  = ''
source += '/*!\n'
source += ' * @file powershell_runner.cpp\n'
source += ' * @brief This file is generated, do not modify directly.\n'
source += ' */\n\n'
source += '#include "powershell_runner.h"\n\n'
source += '#pragma message("Compiling PowerShellRunner into app. Size: {0}")\n\n'.format(len(binary))
source += 'unsigned char PowerShellRunnerDll[{0}] =\n'.format(size_var)
source += '{\n\t'

blobs = []
for c in chunks(binary, 12):
  blobs += [', '.join(['0x' + b.encode('hex') for b in c])]
source += ',\n\t'.join(blobs)
source += '\n};\n\n'

header_path = os.path.join(target_path, 'powershell_runner.h')
source_path = os.path.join(target_path, 'powershell_runner.cpp')

write_all(header_path, header)
write_all(source_path, source)

print "[+] Content written. .NET Binary is {0} bytes".format(len(binary))
