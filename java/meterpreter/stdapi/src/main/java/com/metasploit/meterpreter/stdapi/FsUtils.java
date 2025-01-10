package com.metasploit.meterpreter.stdapi;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;

public class FsUtils {
    public static boolean isSymlink(File file) throws IOException {
        String osName = System.getProperty("os.name");
        if (osName != null && osName.toLowerCase().contains("windows") && isWindowsSymlink(file)) {
            return true;
        }

        File canon;
        if (file.getParent() == null) {
            canon = file;
        } else {
            File canonDir = file.getParentFile().getCanonicalFile();
            canon = new File(canonDir, file.getName());
        }

        return !canon.getCanonicalFile().equals(canon.getAbsoluteFile());
    }

    private static boolean isWindowsSymlink(File file) {
        // this uses reflection to access the java.nio.file classes necessary that are available on Java 7+
        try {
            // first check using isSymbolicLink
            Class<?> filesClass = Class.forName("java.nio.file.Files");
            Class<?> pathClass = Class.forName("java.nio.file.Path");

            Method isSymbolicLinkMethod = filesClass.getMethod("isSymbolicLink", pathClass);
            Method toPathMethod = File.class.getMethod("toPath");

            Object path = toPathMethod.invoke(file);
            if ((Boolean)isSymbolicLinkMethod.invoke(null, path)) {
                return true;
            }

            // next check if the target is a junction because isSymbolicLink doesn't handle that
            Class<?> linkOptionClass = Class.forName("java.nio.file.LinkOption");
            Object linkOptionArray = java.lang.reflect.Array.newInstance(linkOptionClass, 0);
            Method toRealPath = pathClass.getMethod("toRealPath", linkOptionArray.getClass());
            Object realPath = toRealPath.invoke(path, linkOptionArray);

            // toRealPath resolves junctions so the result will be different
            Method equalsMethod = pathClass.getMethod("equals", Object.class);
            if (!(Boolean)equalsMethod.invoke(path, realPath)) {
                return true;
            }
        } catch (ReflectiveOperationException e) {
        }
        return false;
    }
}
