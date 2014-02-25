LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := dalvikstager
LOCAL_SRC_FILES := dalvikstager.c

include $(BUILD_SHARED_LIBRARY)
