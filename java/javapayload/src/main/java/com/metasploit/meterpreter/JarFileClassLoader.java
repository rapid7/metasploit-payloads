package com.metasploit.meterpreter;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipEntry;

public class JarFileClassLoader extends ClassLoader {

    HashMap<String, byte[]> resourceBytes = new HashMap();

    public void addJarFile(byte[] jarFile) throws java.io.IOException {
        ZipInputStream zipReader = new ZipInputStream(new ByteArrayInputStream(jarFile));
        ZipEntry zipEntry;
        while ((zipEntry = zipReader.getNextEntry()) != null) {
            String name = zipEntry.getName();
            String packagedName = name;
            ByteArrayOutputStream resourceStream = new ByteArrayOutputStream();
            final byte[] bytes = new byte[10000];

            int result;
            while ((result = zipReader.read(bytes, 0, bytes.length)) != -1) {
                resourceStream.write(bytes, 0, result);
            }

            resourceBytes.put(packagedName, resourceStream.toByteArray());
        }
    }

    @Override
    public InputStream getResourceAsStream(String name) {
        if (!resourceBytes.containsKey(name)) {
            return null;
        }
        byte[] resource = (byte[])resourceBytes.get(name);
        return new ByteArrayInputStream(resource);
    }

    @Override
    public Class findClass(String name) throws ClassNotFoundException {
        String packagedName = name.replace(".","/") + ".class";
        if (!resourceBytes.containsKey(packagedName)) {
            throw new ClassNotFoundException();
        }
        byte[] classfile = (byte[])resourceBytes.get(packagedName);
        return defineClass(name, classfile, 0, classfile.length, null);
    }

    @Override
    public Class loadClass(String name) throws ClassNotFoundException {
        // The dynamic loading requires knowledge of this classloader, but
        // the default classloader doesn't know about it; so we bridge that
        // gap by returning our own class when requested.
        if (name.equals(getClass().getName())) {
            return getClass();
        }
        try {
            return super.loadClass(name);
        } catch (ClassNotFoundException e) {
            return findClass(name);
        }
    }
}

