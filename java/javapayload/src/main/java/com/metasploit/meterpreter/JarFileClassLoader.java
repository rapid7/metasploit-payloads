package com.metasploit.meterpreter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipEntry;

public class JarFileClassLoader extends ClassLoader {

    HashMap<String, byte[]> classBytes = new HashMap();

    public void addJarFile(byte[] jarFile) throws java.io.IOException {
        ZipInputStream zipReader = new ZipInputStream(new ByteArrayInputStream(jarFile));
        ZipEntry zipEntry;
        while ((zipEntry = zipReader.getNextEntry()) != null) {
            String name = zipEntry.getName();
            String classSuffix = ".class";
            if (name.endsWith(classSuffix)) {
                ByteArrayOutputStream classStream = new ByteArrayOutputStream();
                final byte[] classfile = new byte[10000];

                int result;
                while ((result = zipReader.read(classfile, 0, classfile.length)) != -1) {
                    classStream.write(classfile, 0, result);
                }

                String packagedName = name.replace("/",".").replace("\\",".").substring(0, name.length() - classSuffix.length());
                classBytes.put(packagedName, classStream.toByteArray());
            }
        }
    }

    @Override
    public Class findClass(String name) throws ClassNotFoundException {
        byte[] classfile = classBytes.getOrDefault(name, null);
        if (classfile == null) {
            throw new ClassNotFoundException();
        }
        return defineClass(name, classfile, 0, classfile.length, null);
    }

    @Override
    public Class loadClass(String name) throws ClassNotFoundException {
        try {
            return super.loadClass(name);
        } catch (ClassNotFoundException e) {
            return findClass(name);
        }
    }
}

